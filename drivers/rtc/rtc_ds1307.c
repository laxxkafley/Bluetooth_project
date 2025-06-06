/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 Arunmani Alagarsamy
 * Author: Arunmani Alagarsamy  <arunmani27100@gmail.com>
 *
 * Copyright (c) 2025 Marcin Lyda <elektromarcin@gmail.com>
 */

#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/rtc.h>
#include <zephyr/logging/log.h>
#include <zephyr/pm/device.h>
#include <zephyr/sys/util.h>

#define DT_DRV_COMPAT maxim_ds1307

LOG_MODULE_REGISTER(ds1307, CONFIG_RTC_LOG_LEVEL);

/* DS1307 registers */
#define DS1307_REG_SECONDS 0x00
#define DS1307_REG_MINUTES 0x01
#define DS1307_REG_HOURS   0x02
#define DS1307_REG_DAY     0x03
#define DS1307_REG_DATE    0x04
#define DS1307_REG_MONTH   0x05
#define DS1307_REG_YEAR    0x06
#define DS1307_REG_CTRL    0x07

/* DS1307 bitmasks */
#define SECONDS_BITS  GENMASK(6, 0)
#define MINUTES_BITS  GENMASK(7, 0)
#define HOURS_BITS    GENMASK(5, 0)
#define DATE_BITS     GENMASK(5, 0)
#define MONTHS_BITS   GENMASK(4, 0)
#define WEEKDAY_BITS  GENMASK(2, 0)
#define YEAR_BITS     GENMASK(7, 0)
#define VALIDATE_24HR BIT(6)

#define CTRL_RS_BITS  GENMASK(1, 0)
#define CTRL_SQWE_BIT BIT(4)

#define SQW_FREQ_1Hz     FIELD_PREP(CTRL_RS_BITS, 0x00)
#define SQW_FREQ_4096Hz  FIELD_PREP(CTRL_RS_BITS, 0x01)
#define SQW_FREQ_8192Hz  FIELD_PREP(CTRL_RS_BITS, 0x02)
#define SQW_FREQ_32768Hz FIELD_PREP(CTRL_RS_BITS, 0x03)

/* SQW frequency property enum values */
#define SQW_PROP_ENUM_1HZ      0
#define SQW_PROP_ENUM_4096HZ   1
#define SQW_PROP_ENUM_8192HZ   2
#define SQW_PROP_ENUM_32768HZ  3
#define SQW_PROP_ENUM_DISABLED 4

struct ds1307_config {
	struct i2c_dt_spec i2c_bus;
	uint8_t sqw_freq;
};

struct ds1307_data {
	struct k_spinlock lock;
};

static int ds1307_set_time(const struct device *dev, const struct rtc_time *tm)
{
	int err;
	uint8_t regs[7];

	struct ds1307_data *data = dev->data;
	const struct ds1307_config *config = dev->config;

	k_spinlock_key_t key = k_spin_lock(&data->lock);

	LOG_DBG("set time: year = %d, mon = %d, mday = %d, wday = %d, hour = %d, "
		"min = %d, sec = %d",
		tm->tm_year, tm->tm_mon, tm->tm_mday, tm->tm_wday, tm->tm_hour, tm->tm_min,
		tm->tm_sec);

	regs[0] = bin2bcd(tm->tm_sec) & SECONDS_BITS;
	regs[1] = bin2bcd(tm->tm_min);
	regs[2] = bin2bcd(tm->tm_hour);
	regs[3] = bin2bcd(tm->tm_wday);
	regs[4] = bin2bcd(tm->tm_mday);
	regs[5] = bin2bcd(tm->tm_mon);
	regs[6] = bin2bcd((tm->tm_year % 100));

	err = i2c_burst_write_dt(&config->i2c_bus, DS1307_REG_SECONDS, regs, sizeof(regs));

	k_spin_unlock(&data->lock, key);

	return err;
}

static int ds1307_get_time(const struct device *dev, struct rtc_time *timeptr)
{
	int err;
	uint8_t regs[7];

	struct ds1307_data *data = dev->data;
	const struct ds1307_config *config = dev->config;

	k_spinlock_key_t key = k_spin_lock(&data->lock);

	err = i2c_burst_read_dt(&config->i2c_bus, DS1307_REG_SECONDS, regs, sizeof(regs));
	if (err != 0) {
		goto unlock;
	}

	timeptr->tm_sec = bcd2bin(regs[0] & SECONDS_BITS);
	timeptr->tm_min = bcd2bin(regs[1] & MINUTES_BITS);
	timeptr->tm_hour = bcd2bin(regs[2] & HOURS_BITS); /* 24hr mode */
	timeptr->tm_wday = bcd2bin(regs[3] & WEEKDAY_BITS);
	timeptr->tm_mday = bcd2bin(regs[4] & DATE_BITS);
	timeptr->tm_mon = bcd2bin(regs[5] & MONTHS_BITS);
	timeptr->tm_year = bcd2bin(regs[6] & YEAR_BITS);
	timeptr->tm_year = timeptr->tm_year + 100;

	/* Not used */
	timeptr->tm_nsec = 0;
	timeptr->tm_isdst = -1;
	timeptr->tm_yday = -1;

	/* Validate the chip in 24hr mode */
	if (regs[2] & VALIDATE_24HR) {
		err = -ENODATA;
		goto unlock;
	}

	LOG_DBG("get time: year = %d, mon = %d, mday = %d, wday = %d, hour = %d, "
		"min = %d, sec = %d",
		timeptr->tm_year, timeptr->tm_mon, timeptr->tm_mday, timeptr->tm_wday,
		timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);

unlock:
	k_spin_unlock(&data->lock, key);

	return err;
}

static DEVICE_API(rtc, ds1307_driver_api) = {
	.set_time = ds1307_set_time,
	.get_time = ds1307_get_time,
};

static int ds1307_init(const struct device *dev)
{
	int err;
	uint8_t reg_val;
	const struct ds1307_config *config = dev->config;

	if (!i2c_is_ready_dt(&config->i2c_bus)) {
		LOG_ERR("I2C bus not ready");
		return -ENODEV;
	}

	/* Configure SQW output frequency */
	reg_val = CTRL_SQWE_BIT;
	switch (config->sqw_freq) {
	case SQW_PROP_ENUM_1HZ:
		reg_val |= SQW_FREQ_1Hz;
		break;
	case SQW_PROP_ENUM_4096HZ:
		reg_val |= SQW_FREQ_4096Hz;
		break;
	case SQW_PROP_ENUM_8192HZ:
		reg_val |= SQW_FREQ_8192Hz;
		break;
	case SQW_PROP_ENUM_32768HZ:
		reg_val |= SQW_FREQ_32768Hz;
		break;
	case SQW_PROP_ENUM_DISABLED:
	default:
		reg_val &= ~CTRL_SQWE_BIT;
		break;
	}
	err = i2c_reg_write_byte_dt(&config->i2c_bus, DS1307_REG_CTRL, reg_val);
	if (err < 0) {
		LOG_ERR("Error: Configure SQW: %d", err);
	}

	/* Ensure Clock Halt = 0 */
	err = i2c_reg_read_byte_dt(&config->i2c_bus, DS1307_REG_SECONDS, &reg_val);
	if (err < 0) {
		LOG_ERR("Error: Read SECONDS/Clock Halt register: %d", err);
	}
	if (reg_val & ~SECONDS_BITS) {
		/* Clock Halt bit is set */
		err = i2c_reg_write_byte_dt(&config->i2c_bus, DS1307_REG_SECONDS,
					    reg_val & SECONDS_BITS);
		if (err < 0) {
			LOG_ERR("Error: Clear Clock Halt bit: %d", err);
		}
	}

	return 0;
}

#define DS1307_DEFINE(inst)                                                                        \
	static struct ds1307_data ds1307_data_##inst;                                              \
	static const struct ds1307_config ds1307_config_##inst = {                                 \
		.i2c_bus = I2C_DT_SPEC_INST_GET(inst),                                             \
		.sqw_freq = DT_INST_ENUM_IDX_OR(inst, sqw_frequency, SQW_PROP_ENUM_DISABLED)	   \
	};											   \
	DEVICE_DT_INST_DEFINE(inst, &ds1307_init, NULL, &ds1307_data_##inst,                       \
			      &ds1307_config_##inst, POST_KERNEL, CONFIG_RTC_INIT_PRIORITY,        \
			      &ds1307_driver_api);

DT_INST_FOREACH_STATUS_OKAY(DS1307_DEFINE)
