// SPDX-License-Identifier: GPL-2.0
/*
 * CBQRI bandwidth-controller schemata interface tests (MB_MIN, MB_WGHT)
 *
 * Copyright (C) 2026 Tenstorrent AI ULC
 */
#include <fcntl.h>
#include <limits.h>

#include "resctrl.h"

#define MB_MIN_RESOURCE		"MB_MIN"
#define MB_WGHT_RESOURCE	"MB_WGHT"
#define TEST_GROUP		"cbqri_bw_c1"

#define CBQRI_MB_MIN_MIN_BW	1U
#define CBQRI_MB_MIN_BW_GRAN	1U

#define CBQRI_MB_WGHT_MIN_BW	0U
#define CBQRI_MB_WGHT_MAX_BW	255U
#define CBQRI_MB_WGHT_BW_GRAN	1U

/* Parse <resource>:<dom>=<val>;... from an opened schemata file. */
static int parse_schemata_value(FILE *fp, const char *resource,
				int domain_id, unsigned int *val)
{
	char line[1024];
	char *colon, *tok, *res;

	while (fgets(line, sizeof(line), fp)) {
		colon = strchr(line, ':');
		if (!colon)
			continue;
		*colon++ = '\0';
		/* Trim leading whitespace from the resource name. */
		res = line;
		while (*res == ' ' || *res == '\t')
			res++;
		if (strcmp(res, resource))
			continue;

		for (tok = strtok(colon, ";\n"); tok;
		     tok = strtok(NULL, ";\n")) {
			int dom;
			unsigned int v;

			if (sscanf(tok, "%d=%u", &dom, &v) == 2 &&
			    dom == domain_id) {
				*val = v;
				return 0;
			}
		}
		return -1;
	}
	return -1;
}

static void schemata_path(char *out, size_t len, const char *ctrlgrp)
{
	if (ctrlgrp && *ctrlgrp)
		snprintf(out, len, "%s/%s/schemata", RESCTRL_PATH, ctrlgrp);
	else
		snprintf(out, len, "%s/schemata", RESCTRL_PATH);
}

static int read_schemata_value(const char *ctrlgrp, const char *resource,
			       int domain_id, unsigned int *val)
{
	char path[PATH_MAX];
	FILE *fp;
	int ret;

	schemata_path(path, sizeof(path), ctrlgrp);

	fp = fopen(path, "r");
	if (!fp) {
		ksft_print_msg("Failed to open %s: %s\n",
			       path, strerror(errno));
		return -1;
	}

	ret = parse_schemata_value(fp, resource, domain_id, val);
	fclose(fp);

	if (ret)
		ksft_print_msg("Could not find %s:%d in %s\n",
			       resource, domain_id, path);
	return ret;
}

/*
 * Write a schemata line expecting the kernel to reject it. Returns the
 * errno observed on the expected failure, or -1 if the write
 * unexpectedly succeeded or the setup itself failed.
 */
static int write_schemata_expect_fail(const char *ctrlgrp, const char *value,
				      int cpu_no, const char *resource)
{
	char path[PATH_MAX], schema[256];
	int domain_id, fd, len, err;
	ssize_t ret;

	if (get_domain_id(resource, cpu_no, &domain_id) < 0)
		return -1;

	schemata_path(path, sizeof(path), ctrlgrp);

	len = snprintf(schema, sizeof(schema), "%s:%d=%s\n",
		       resource, domain_id, value);
	if (len < 0 || (size_t)len >= sizeof(schema))
		return -1;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	errno = 0;
	ret = write(fd, schema, len);
	err = errno;
	close(fd);

	if (ret >= 0) {
		ksft_print_msg("Unexpected success writing \"%s\" to %s\n",
			       schema, path);
		return -1;
	}
	return err;
}

static void cleanup_group(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", RESCTRL_PATH, name);
	if (rmdir(path) < 0 && errno != ENOENT)
		ksft_print_msg("rmdir %s: %s\n", path, strerror(errno));
}

static int create_test_group(void)
{
	char path[PATH_MAX];

	cleanup_group(TEST_GROUP);
	snprintf(path, sizeof(path), "%s/%s", RESCTRL_PATH, TEST_GROUP);
	if (mkdir(path, 0755) < 0) {
		ksft_print_msg("mkdir %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* MB_MIN interface test */
static int mb_min_run_test(const struct resctrl_test *test,
			   const struct user_params *uparams)
{
	unsigned int min_bw, bw_gran, num_closids, val, orig_root;
	char path[PATH_MAX], buf[32];
	int domain_id, err, ret = -1;
	struct stat st;

	if (get_domain_id(MB_MIN_RESOURCE, uparams->cpu, &domain_id) < 0) {
		ksft_print_msg("Could not get MB_MIN domain id for CPU %d\n",
			       uparams->cpu);
		return -1;
	}

	if (resource_info_unsigned_get(MB_MIN_RESOURCE, "min_bandwidth",
				       &min_bw) < 0)
		return -1;
	if (min_bw != CBQRI_MB_MIN_MIN_BW) {
		ksft_print_msg("info/MB_MIN/min_bandwidth = %u, expected %u\n",
			       min_bw, CBQRI_MB_MIN_MIN_BW);
		return -1;
	}

	if (resource_info_unsigned_get(MB_MIN_RESOURCE, "bandwidth_gran",
				       &bw_gran) < 0)
		return -1;
	if (bw_gran != CBQRI_MB_MIN_BW_GRAN) {
		ksft_print_msg("info/MB_MIN/bandwidth_gran = %u, expected %u\n",
			       bw_gran, CBQRI_MB_MIN_BW_GRAN);
		return -1;
	}

	if (resource_info_unsigned_get(MB_MIN_RESOURCE, "num_closids",
				       &num_closids) < 0)
		return -1;
	if (num_closids == 0) {
		ksft_print_msg("info/MB_MIN/num_closids = 0\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/%s/delay_linear",
		 INFO_PATH, MB_MIN_RESOURCE);
	if (stat(path, &st) < 0) {
		ksft_print_msg("info/MB_MIN/delay_linear missing: %s\n",
			       strerror(errno));
		return -1;
	}

	/* Capture root MB_MIN so the test can restore it. */
	if (read_schemata_value("", MB_MIN_RESOURCE, domain_id, &orig_root))
		return -1;

	if (create_test_group())
		goto out;

	if (read_schemata_value(TEST_GROUP, MB_MIN_RESOURCE, domain_id, &val))
		goto out;
	if (val != CBQRI_MB_MIN_MIN_BW) {
		ksft_print_msg("New group MB_MIN default = %u, expected %u\n",
			       val, CBQRI_MB_MIN_MIN_BW);
		goto out;
	}

	/* sum(MB_MIN) == MRBWB at mount; free a block before writing 2. */
	snprintf(buf, sizeof(buf), "%u", orig_root - 1);
	if (write_schemata("", buf, uparams->cpu, MB_MIN_RESOURCE) < 0)
		goto out;

	if (write_schemata(TEST_GROUP, "2", uparams->cpu, MB_MIN_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, MB_MIN_RESOURCE, domain_id, &val))
		goto out;
	if (val != 2) {
		ksft_print_msg("MB_MIN round-trip: wrote 2, read %u\n", val);
		goto out;
	}

	/* Below-min_bw rejected with EINVAL. */
	err = write_schemata_expect_fail(TEST_GROUP, "0", uparams->cpu,
					 MB_MIN_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MB_MIN=0 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/* Above-max_bw rejected with EINVAL. */
	err = write_schemata_expect_fail(TEST_GROUP, "0xffffff", uparams->cpu,
					 MB_MIN_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MB_MIN above-max write: expected EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/* sum(MB_MIN) > MRBWB rejected with EINVAL by the arch layer. */
	if (orig_root >= 3) {
		err = write_schemata_expect_fail(TEST_GROUP, "3", uparams->cpu,
						 MB_MIN_RESOURCE);
		if (err != EINVAL) {
			ksft_print_msg("MB_MIN sum overflow: expected EINVAL, got %d (%s)\n",
				       err, err > 0 ? strerror(err) : "setup error");
			goto out;
		}
	}

	ret = 0;
out:
	/* Lower test-group MB_MIN before rmdir; the CSR persists past CLOSID free. */
	write_schemata(TEST_GROUP, "1", uparams->cpu, MB_MIN_RESOURCE);
	cleanup_group(TEST_GROUP);
	snprintf(buf, sizeof(buf), "%u", orig_root);
	if (write_schemata("", buf, uparams->cpu, MB_MIN_RESOURCE) < 0)
		ksft_print_msg("Failed to restore root MB_MIN to %u\n",
			       orig_root);
	return ret;
}

static bool mb_min_feature_check(const struct resctrl_test *test)
{
	return resctrl_resource_exists(MB_MIN_RESOURCE);
}

static void mb_min_cleanup(void)
{
	cleanup_group(TEST_GROUP);
}

/* MB_WGHT interface test */
static int mb_wght_run_test(const struct resctrl_test *test,
			    const struct user_params *uparams)
{
	static const unsigned int test_values[] = { 0, 1, 128, 255 };
	unsigned int min_bw, bw_gran, num_closids, val, mb_min_val;
	unsigned int orig_root_mb_wght, orig_root_mb_min = 0;
	int domain_id, mb_min_domain_id = -1, err, ret = -1;
	bool mb_min_modified = false;
	char buf[32];
	size_t i;

	if (get_domain_id(MB_WGHT_RESOURCE, uparams->cpu, &domain_id) < 0) {
		ksft_print_msg("Could not get MB_WGHT domain id for CPU %d\n",
			       uparams->cpu);
		return -1;
	}

	if (resource_info_unsigned_get(MB_WGHT_RESOURCE, "min_bandwidth",
				       &min_bw) < 0)
		return -1;
	if (min_bw != CBQRI_MB_WGHT_MIN_BW) {
		ksft_print_msg("info/MB_WGHT/min_bandwidth = %u, expected %u\n",
			       min_bw, CBQRI_MB_WGHT_MIN_BW);
		return -1;
	}

	if (resource_info_unsigned_get(MB_WGHT_RESOURCE, "bandwidth_gran",
				       &bw_gran) < 0)
		return -1;
	if (bw_gran != CBQRI_MB_WGHT_BW_GRAN) {
		ksft_print_msg("info/MB_WGHT/bandwidth_gran = %u, expected %u\n",
			       bw_gran, CBQRI_MB_WGHT_BW_GRAN);
		return -1;
	}

	if (resource_info_unsigned_get(MB_WGHT_RESOURCE, "num_closids",
				       &num_closids) < 0)
		return -1;
	if (num_closids == 0) {
		ksft_print_msg("info/MB_WGHT/num_closids = 0\n");
		return -1;
	}

	if (read_schemata_value("", MB_WGHT_RESOURCE, domain_id,
				&orig_root_mb_wght))
		return -1;

	if (resctrl_resource_exists(MB_MIN_RESOURCE)) {
		if (get_domain_id(MB_MIN_RESOURCE, uparams->cpu,
				  &mb_min_domain_id) < 0)
			return -1;
		if (read_schemata_value("", MB_MIN_RESOURCE, mb_min_domain_id,
					&orig_root_mb_min))
			return -1;
	}

	if (create_test_group())
		goto out;

	if (read_schemata_value(TEST_GROUP, MB_WGHT_RESOURCE, domain_id,
				&val))
		goto out;
	if (val != CBQRI_MB_WGHT_MAX_BW) {
		ksft_print_msg("MB_WGHT default = %u, expected %u\n",
			       val, CBQRI_MB_WGHT_MAX_BW);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(test_values); i++) {
		snprintf(buf, sizeof(buf), "%u", test_values[i]);
		if (write_schemata(TEST_GROUP, buf, uparams->cpu,
				   MB_WGHT_RESOURCE) < 0)
			goto out;
		if (read_schemata_value(TEST_GROUP, MB_WGHT_RESOURCE,
					domain_id, &val))
			goto out;
		if (val != test_values[i]) {
			ksft_print_msg("MB_WGHT round-trip: wrote %u, read %u\n",
				       test_values[i], val);
			goto out;
		}
	}

	/* Above-max_bw rejected with EINVAL. */
	err = write_schemata_expect_fail(TEST_GROUP, "256", uparams->cpu,
					 MB_WGHT_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MB_WGHT=256 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}
	err = write_schemata_expect_fail(TEST_GROUP, "9999", uparams->cpu,
					 MB_WGHT_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MB_WGHT=9999 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/* No sum constraint: two groups can both hold max weight 255. */
	if (orig_root_mb_wght != 255) {
		ksft_print_msg("root MB_WGHT = %u, expected default 255\n",
			       orig_root_mb_wght);
		goto out;
	}
	if (write_schemata(TEST_GROUP, "255", uparams->cpu,
			   MB_WGHT_RESOURCE) < 0) {
		ksft_print_msg("MB_WGHT=255 on %s should succeed\n",
			       TEST_GROUP);
		goto out;
	}

	/* Independence: MB_MIN and MB_WGHT writes don't affect each other. */
	if (mb_min_domain_id < 0 || orig_root_mb_min < 3) {
		ret = 0;
		goto out;
	}

	snprintf(buf, sizeof(buf), "%u", orig_root_mb_min - 2);
	if (write_schemata("", buf, uparams->cpu, MB_MIN_RESOURCE) < 0)
		goto out;
	mb_min_modified = true;

	if (write_schemata(TEST_GROUP, "3", uparams->cpu, MB_MIN_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, MB_WGHT_RESOURCE, domain_id, &val))
		goto out;
	if (val != 255) {
		ksft_print_msg("MB_WGHT changed after MB_MIN write: %u (expected 255)\n",
			       val);
		goto out;
	}

	if (write_schemata(TEST_GROUP, "100", uparams->cpu, MB_WGHT_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, MB_MIN_RESOURCE, mb_min_domain_id,
				&mb_min_val))
		goto out;
	if (mb_min_val != 3) {
		ksft_print_msg("MB_MIN changed after MB_WGHT write: %u (expected 3)\n",
			       mb_min_val);
		goto out;
	}

	ret = 0;
out:
	/* See mb_min_run_test(): lower test-group MB_MIN before rmdir. */
	if (mb_min_modified)
		write_schemata(TEST_GROUP, "1", uparams->cpu, MB_MIN_RESOURCE);
	cleanup_group(TEST_GROUP);
	if (mb_min_modified) {
		snprintf(buf, sizeof(buf), "%u", orig_root_mb_min);
		if (write_schemata("", buf, uparams->cpu, MB_MIN_RESOURCE) < 0)
			ksft_print_msg("Failed to restore root MB_MIN to %u\n",
				       orig_root_mb_min);
	}
	return ret;
}

static bool mb_wght_feature_check(const struct resctrl_test *test)
{
	return resctrl_resource_exists(MB_WGHT_RESOURCE);
}

static void mb_wght_cleanup(void)
{
	cleanup_group(TEST_GROUP);
}

struct resctrl_test mb_min_test = {
	.name = "MB_MIN",
	.resource = MB_MIN_RESOURCE,
	.feature_check = mb_min_feature_check,
	.run_test = mb_min_run_test,
	.cleanup = mb_min_cleanup,
};

struct resctrl_test mb_wght_test = {
	.name = "MB_WGHT",
	.resource = MB_WGHT_RESOURCE,
	.feature_check = mb_wght_feature_check,
	.run_test = mb_wght_run_test,
	.cleanup = mb_wght_cleanup,
};
