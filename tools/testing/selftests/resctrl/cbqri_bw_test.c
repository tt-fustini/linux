// SPDX-License-Identifier: GPL-2.0
/*
 * CBQRI RBWB and MWEIGHT schemata interface tests
 *
 * Exercises the two resctrl resource types added for the RISC-V CBQRI
 * bandwidth controllers:
 *
 *   RBWB    - Reserved Bandwidth Blocks (CBQRI §4.5). Per-group
 *             guaranteed minimum with a sum(Rbwb) <= MRBWB cross-group
 *             cap enforced by the arch layer (returns -ENOSPC on
 *             overflow). Per-group range [min_bw=1, max_bw=MRBWB],
 *             bw_gran=1.
 *   MWEIGHT - Opportunistic bandwidth weight, range [0..255], no sum
 *             constraint. bw_gran=1.
 *
 * The tests validate schemata parsing, info files, default values on
 * mkdir, and the sum-constraint rejection path. They require no
 * architecture-specific perf counters and run purely through the
 * resctrl filesystem.
 */
#include <fcntl.h>
#include <limits.h>

#include "resctrl.h"

#define RBWB_RESOURCE		"RBWB"
#define MWEIGHT_RESOURCE	"MWEIGHT"
#define TEST_GROUP		"cbqri_bw_c1"

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

static int read_schemata_value(const char *ctrlgrp, const char *resource,
			       int domain_id, unsigned int *val)
{
	char path[PATH_MAX];
	FILE *fp;
	int ret;

	if (ctrlgrp && *ctrlgrp)
		snprintf(path, sizeof(path), "%s/%s/schemata",
			 RESCTRL_PATH, ctrlgrp);
	else
		snprintf(path, sizeof(path), "%s/schemata", RESCTRL_PATH);

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

	if (ctrlgrp && *ctrlgrp)
		snprintf(path, sizeof(path), "%s/%s/schemata",
			 RESCTRL_PATH, ctrlgrp);
	else
		snprintf(path, sizeof(path), "%s/schemata", RESCTRL_PATH);

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

/* RBWB interface test */
static int rbwb_run_test(const struct resctrl_test *test,
			 const struct user_params *uparams)
{
	unsigned int min_bw, bw_gran, num_closids, val, orig_root;
	char path[PATH_MAX], buf[32];
	int domain_id, err, ret = -1;
	struct stat st;

	if (get_domain_id(RBWB_RESOURCE, uparams->cpu, &domain_id) < 0) {
		ksft_print_msg("Could not get RBWB domain id for CPU %d\n",
			       uparams->cpu);
		return -1;
	}

	if (resource_info_unsigned_get(RBWB_RESOURCE, "min_bandwidth",
				       &min_bw) < 0)
		return -1;
	if (min_bw != 1) {
		ksft_print_msg("info/RBWB/min_bandwidth = %u, expected 1\n",
			       min_bw);
		return -1;
	}

	if (resource_info_unsigned_get(RBWB_RESOURCE, "bandwidth_gran",
				       &bw_gran) < 0)
		return -1;
	if (bw_gran != 1) {
		ksft_print_msg("info/RBWB/bandwidth_gran = %u, expected 1\n",
			       bw_gran);
		return -1;
	}

	if (resource_info_unsigned_get(RBWB_RESOURCE, "num_closids",
				       &num_closids) < 0)
		return -1;
	if (num_closids == 0) {
		ksft_print_msg("info/RBWB/num_closids = 0\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/%s/delay_linear",
		 INFO_PATH, RBWB_RESOURCE);
	if (stat(path, &st) < 0) {
		ksft_print_msg("info/RBWB/delay_linear missing: %s\n",
			       strerror(errno));
		return -1;
	}

	/*
	 * With only the root group present, root RBWB equals MRBWB (the
	 * per-domain hardware budget). Capture it so the test can restore.
	 */
	if (read_schemata_value("", RBWB_RESOURCE, domain_id, &orig_root))
		return -1;

	if (create_test_group())
		goto out;

	/* Default on mkdir is min_bw=1 (membw.default_ctrl = min_bw for RBWB). */
	if (read_schemata_value(TEST_GROUP, RBWB_RESOURCE, domain_id, &val))
		goto out;
	if (val != 1) {
		ksft_print_msg("New group RBWB default = %u, expected 1\n",
			       val);
		goto out;
	}

	/*
	 * CBQRI initialises every RCID to at least 1 block so sum(RBWB) ==
	 * MRBWB at mount. Free one block from root before writing 2 to the
	 * test group.
	 */
	snprintf(buf, sizeof(buf), "%u", orig_root - 1);
	if (write_schemata("", buf, uparams->cpu, RBWB_RESOURCE) < 0)
		goto out;

	if (write_schemata(TEST_GROUP, "2", uparams->cpu, RBWB_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, RBWB_RESOURCE, domain_id, &val))
		goto out;
	if (val != 2) {
		ksft_print_msg("RBWB round-trip: wrote 2, read %u\n", val);
		goto out;
	}

	/* Below-min_bw is rejected by bw_validate() with -EINVAL. */
	err = write_schemata_expect_fail(TEST_GROUP, "0", uparams->cpu,
					 RBWB_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("RBWB=0 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/*
	 * A value well beyond max_bw is rejected by bw_validate() with
	 * -EINVAL, before the arch-layer sum check runs. 0xffffff is far
	 * above any realistic MRBWB.
	 */
	err = write_schemata_expect_fail(TEST_GROUP, "0xffffff", uparams->cpu,
					 RBWB_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("RBWB above-max write: expected EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/*
	 * A valid-per-group value that pushes sum(RBWB) above MRBWB is
	 * rejected by the arch layer with -ENOSPC. After the round-trip
	 * above, root + test == MRBWB; writing test+1 overflows the sum.
	 */
	if (orig_root >= 3) {
		err = write_schemata_expect_fail(TEST_GROUP, "3", uparams->cpu,
						 RBWB_RESOURCE);
		if (err != ENOSPC) {
			ksft_print_msg("RBWB sum overflow: expected ENOSPC, got %d (%s)\n",
				       err, err > 0 ? strerror(err) : "setup error");
			goto out;
		}
	}

	ret = 0;
out:
	cleanup_group(TEST_GROUP);
	snprintf(buf, sizeof(buf), "%u", orig_root);
	if (write_schemata("", buf, uparams->cpu, RBWB_RESOURCE) < 0)
		ksft_print_msg("Failed to restore root RBWB to %u\n",
			       orig_root);
	return ret;
}

static bool rbwb_feature_check(const struct resctrl_test *test)
{
	return resctrl_resource_exists(RBWB_RESOURCE);
}

static void rbwb_cleanup(void)
{
	cleanup_group(TEST_GROUP);
}

/* MWEIGHT interface test */
static int mweight_run_test(const struct resctrl_test *test,
			    const struct user_params *uparams)
{
	static const unsigned int test_values[] = { 0, 1, 128, 255 };
	unsigned int min_bw, bw_gran, num_closids, val, rbwb_val;
	unsigned int orig_root_mweight, orig_root_rbwb = 0;
	int domain_id, rbwb_domain_id = -1, err, ret = -1;
	bool rbwb_modified = false;
	char buf[32];
	size_t i;

	if (get_domain_id(MWEIGHT_RESOURCE, uparams->cpu, &domain_id) < 0) {
		ksft_print_msg("Could not get MWEIGHT domain id for CPU %d\n",
			       uparams->cpu);
		return -1;
	}

	if (resource_info_unsigned_get(MWEIGHT_RESOURCE, "min_bandwidth",
				       &min_bw) < 0)
		return -1;
	if (min_bw != 0) {
		ksft_print_msg("info/MWEIGHT/min_bandwidth = %u, expected 0\n",
			       min_bw);
		return -1;
	}

	if (resource_info_unsigned_get(MWEIGHT_RESOURCE, "bandwidth_gran",
				       &bw_gran) < 0)
		return -1;
	if (bw_gran != 1) {
		ksft_print_msg("info/MWEIGHT/bandwidth_gran = %u, expected 1\n",
			       bw_gran);
		return -1;
	}

	if (resource_info_unsigned_get(MWEIGHT_RESOURCE, "num_closids",
				       &num_closids) < 0)
		return -1;
	if (num_closids == 0) {
		ksft_print_msg("info/MWEIGHT/num_closids = 0\n");
		return -1;
	}

	if (read_schemata_value("", MWEIGHT_RESOURCE, domain_id,
				&orig_root_mweight))
		return -1;

	if (resctrl_resource_exists(RBWB_RESOURCE)) {
		if (get_domain_id(RBWB_RESOURCE, uparams->cpu,
				  &rbwb_domain_id) < 0)
			return -1;
		if (read_schemata_value("", RBWB_RESOURCE, rbwb_domain_id,
					&orig_root_rbwb))
			return -1;
	}

	if (create_test_group())
		goto out;

	/*
	 * Default on mkdir equals resctrl_get_default_ctrl(), which for
	 * MWEIGHT is max_bw=255 (qos_init_mweight_resource() leaves
	 * membw.default_ctrl at zero so the resctrl helper falls back to
	 * max_bw).
	 */
	if (read_schemata_value(TEST_GROUP, MWEIGHT_RESOURCE, domain_id,
				&val))
		goto out;
	if (val != 255) {
		ksft_print_msg("MWEIGHT default = %u, expected 255\n", val);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(test_values); i++) {
		snprintf(buf, sizeof(buf), "%u", test_values[i]);
		if (write_schemata(TEST_GROUP, buf, uparams->cpu,
				   MWEIGHT_RESOURCE) < 0)
			goto out;
		if (read_schemata_value(TEST_GROUP, MWEIGHT_RESOURCE,
					domain_id, &val))
			goto out;
		if (val != test_values[i]) {
			ksft_print_msg("MWEIGHT round-trip: wrote %u, read %u\n",
				       test_values[i], val);
			goto out;
		}
	}

	/* Above-max_bw rejected with EINVAL. */
	err = write_schemata_expect_fail(TEST_GROUP, "256", uparams->cpu,
					 MWEIGHT_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MWEIGHT=256 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}
	err = write_schemata_expect_fail(TEST_GROUP, "9999", uparams->cpu,
					 MWEIGHT_RESOURCE);
	if (err != EINVAL) {
		ksft_print_msg("MWEIGHT=9999 should fail with EINVAL, got %d (%s)\n",
			       err, err > 0 ? strerror(err) : "setup error");
		goto out;
	}

	/*
	 * No sum constraint: root defaults to 255, so setting TEST_GROUP
	 * to 255 should succeed even though two groups both hold the
	 * maximum weight simultaneously.
	 */
	if (orig_root_mweight != 255) {
		ksft_print_msg("root MWEIGHT = %u, expected default 255\n",
			       orig_root_mweight);
		goto out;
	}
	if (write_schemata(TEST_GROUP, "255", uparams->cpu,
			   MWEIGHT_RESOURCE) < 0) {
		ksft_print_msg("MWEIGHT=255 on %s should succeed\n",
			       TEST_GROUP);
		goto out;
	}

	/*
	 * Independence: RBWB and MWEIGHT writes do not affect each other.
	 * CBQRI initialises every RCID with at least 1 block so sum(RBWB)
	 * == MRBWB at mount; free 2 blocks from the root before writing 3
	 * to the test group.
	 */
	if (rbwb_domain_id < 0 || orig_root_rbwb < 3) {
		ret = 0;
		goto out;
	}

	snprintf(buf, sizeof(buf), "%u", orig_root_rbwb - 2);
	if (write_schemata("", buf, uparams->cpu, RBWB_RESOURCE) < 0)
		goto out;
	rbwb_modified = true;

	if (write_schemata(TEST_GROUP, "3", uparams->cpu, RBWB_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, MWEIGHT_RESOURCE, domain_id, &val))
		goto out;
	if (val != 255) {
		ksft_print_msg("MWEIGHT changed after RBWB write: %u (expected 255)\n",
			       val);
		goto out;
	}

	if (write_schemata(TEST_GROUP, "100", uparams->cpu, MWEIGHT_RESOURCE) < 0)
		goto out;
	if (read_schemata_value(TEST_GROUP, RBWB_RESOURCE, rbwb_domain_id,
				&rbwb_val))
		goto out;
	if (rbwb_val != 3) {
		ksft_print_msg("RBWB changed after MWEIGHT write: %u (expected 3)\n",
			       rbwb_val);
		goto out;
	}

	ret = 0;
out:
	cleanup_group(TEST_GROUP);
	if (rbwb_modified) {
		snprintf(buf, sizeof(buf), "%u", orig_root_rbwb);
		if (write_schemata("", buf, uparams->cpu, RBWB_RESOURCE) < 0)
			ksft_print_msg("Failed to restore root RBWB to %u\n",
				       orig_root_rbwb);
	}
	return ret;
}

static bool mweight_feature_check(const struct resctrl_test *test)
{
	return resctrl_resource_exists(MWEIGHT_RESOURCE);
}

static void mweight_cleanup(void)
{
	cleanup_group(TEST_GROUP);
}

struct resctrl_test rbwb_test = {
	.name = "RBWB",
	.resource = RBWB_RESOURCE,
	.feature_check = rbwb_feature_check,
	.run_test = rbwb_run_test,
	.cleanup = rbwb_cleanup,
};

struct resctrl_test mweight_test = {
	.name = "MWEIGHT",
	.resource = MWEIGHT_RESOURCE,
	.feature_check = mweight_feature_check,
	.run_test = mweight_run_test,
	.cleanup = mweight_cleanup,
};
