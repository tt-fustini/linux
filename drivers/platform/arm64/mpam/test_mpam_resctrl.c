// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 Arm Ltd.
/* This file is intended to be included into mpam_resctrl.c */

#include <kunit/test.h>

static void test_get_mba_granularity(struct kunit *test)
{
	int ret;
	struct mpam_props fake_props = {0};

	/* Use MBW_PBM */
	mpam_set_feature(mpam_feat_mbw_part, &fake_props);

	/* 0 bits means the control is unconfigurable */
	fake_props.mbw_pbm_bits = 0;
	KUNIT_EXPECT_FALSE(test, mba_class_use_mbw_part(&fake_props));

	fake_props.mbw_pbm_bits = 4;
	KUNIT_EXPECT_TRUE(test, mba_class_use_mbw_part(&fake_props));

	/* Granularity saturates at 1% */
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 25);	/* 100% / 4 = 25% */

	fake_props.mbw_pbm_bits = 100;
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 1);	/* 100% / 100 = 1% */

	fake_props.mbw_pbm_bits = 128;
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 1);	/* 100% / 128 = 1% */

	fake_props.mbw_pbm_bits = 4096;	/* architectural maximum */
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 1);	/* 100% / 4096 = 1% */

	/* When MBW_MAX is also supported, Portions are preferred */
	mpam_set_feature(mpam_feat_mbw_max, &fake_props);
	fake_props.bwa_wd = 4;
	KUNIT_EXPECT_TRUE(test, mba_class_use_mbw_part(&fake_props));

	fake_props.features = 0;
	fake_props.mbw_pbm_bits = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_props);

	/* No usable control... */
	fake_props.bwa_wd = 0;
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0);	/* 100% / [0:0] = 0% */

	fake_props.bwa_wd = 1;
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 50);	/* 100% / [1:0] = 50% */

	fake_props.bwa_wd = 2;
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 25);	/* 100% / [2:0] = 25% */

	/* Granularity saturates at 1% */
	fake_props.bwa_wd = 16; /* architectural maximum */
	ret = get_mba_granularity(&fake_props);
	KUNIT_EXPECT_EQ(test, ret, 1);	/* 100% / [16:0] = 1% */
}

static void test_mbw_pbm_to_percent(struct kunit *test)
{
	int ret;
	struct mpam_props fake_props = {0};

	mpam_set_feature(mpam_feat_mbw_part, &fake_props);
	fake_props.mbw_pbm_bits = 4;

	ret = mbw_pbm_to_percent(0x0, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = mbw_pbm_to_percent(0x3, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 50);

	ret = mbw_pbm_to_percent(0x7, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 75);

	fake_props.mbw_pbm_bits = 16; /* architectural maximum */
	ret = mbw_pbm_to_percent(0xffff, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 100);

	fake_props.mbw_pbm_bits = 0;
	ret = mbw_pbm_to_percent(0xff, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_mbw_max_to_percent(struct kunit *test)
{
	u32 ret;
	struct mpam_props fake_props = {0};

	mpam_set_feature(mpam_feat_mbw_max, &fake_props);
	fake_props.bwa_wd = 8;

	ret = mbw_max_to_percent(0xff00, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 100);

	ret = mbw_max_to_percent(0x8000, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 50);

	ret = mbw_max_to_percent(0x0000, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0);

	fake_props.bwa_wd = 16; /* architectural maximum */
	ret = mbw_max_to_percent(0xffff, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 100);
}

static void test_percent_to_mbw_pbm(struct kunit *test)
{
	unsigned long ret;
	struct mpam_props fake_props = {0};

	mpam_set_feature(mpam_feat_mbw_part, &fake_props);
	fake_props.mbw_pbm_bits = 4;

	ret = percent_to_mbw_pbm(100, &fake_props);
	KUNIT_EXPECT_EQ(test, bitmap_weight(&ret, fake_props.mbw_pbm_bits), 4);

	ret = percent_to_mbw_pbm(50, &fake_props);
	KUNIT_EXPECT_EQ(test, bitmap_weight(&ret, fake_props.mbw_pbm_bits), 2);

	ret = percent_to_mbw_pbm(0, &fake_props);
	KUNIT_EXPECT_EQ(test, bitmap_weight(&ret, fake_props.mbw_pbm_bits), 0);

	fake_props.mbw_pbm_bits = 16; /* architectural maximum */
	ret = percent_to_mbw_pbm(100, &fake_props);
	KUNIT_EXPECT_EQ(test, bitmap_weight(&ret, fake_props.mbw_pbm_bits), 16);
}

static void test_percent_to_mbw_max(struct kunit *test)
{
	u32 ret;
	struct mpam_props fake_props = {0};

	mpam_set_feature(mpam_feat_mbw_max, &fake_props);
	fake_props.bwa_wd = 4;

	ret = percent_to_mbw_max(100, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0xf000);

	ret = percent_to_mbw_max(50, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0x8000);

	ret = percent_to_mbw_max(0, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0x0000);

	fake_props.bwa_wd = 16; /* architectural maximum */
	ret = percent_to_mbw_max(100, &fake_props);
	KUNIT_EXPECT_EQ(test, ret, 0xffff);
}

static struct kunit_case mpam_resctrl_test_cases[] = {
	KUNIT_CASE(test_get_mba_granularity),
	KUNIT_CASE(test_mbw_pbm_to_percent),
	KUNIT_CASE(test_mbw_max_to_percent),
	KUNIT_CASE(test_percent_to_mbw_pbm),
	KUNIT_CASE(test_percent_to_mbw_max),
	{}
};

static struct kunit_suite mpam_resctrl_test_suite = {
	.name = "mpam_resctrl_test_suite",
	.test_cases = mpam_resctrl_test_cases,
};

kunit_test_suites(&mpam_resctrl_test_suite);
