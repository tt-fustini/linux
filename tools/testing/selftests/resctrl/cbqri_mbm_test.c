// SPDX-License-Identifier: GPL-2.0
/*
 * CBQRI mbm_total_bytes interface test (mon_features advertisement,
 * file presence per domain, monotonic reads)
 */
#include <dirent.h>
#include <limits.h>

#include "resctrl.h"

#define L3_MON			"L3_MON"
#define MBM_TOTAL_BYTES		"mbm_total_bytes"
#define MBM_LOCAL_BYTES		"mbm_local_bytes"
#define MON_DATA_DIR		RESCTRL_PATH "/mon_data"

static int read_u64_file(const char *path, unsigned long long *val)
{
	FILE *fp;
	int n;

	fp = fopen(path, "r");
	if (!fp) {
		ksft_print_msg("Failed to open %s: %s\n",
			       path, strerror(errno));
		return -1;
	}
	n = fscanf(fp, "%llu", val);
	fclose(fp);

	if (n != 1) {
		ksft_print_msg("Failed to parse u64 from %s\n", path);
		return -1;
	}
	return 0;
}

static int check_mon_features(void)
{
	if (!resctrl_mon_feature_exists(L3_MON, MBM_TOTAL_BYTES)) {
		ksft_print_msg("info/%s/mon_features missing %s\n",
			       L3_MON, MBM_TOTAL_BYTES);
		return -1;
	}
	/* CBQRI does not advertise mbm_local_bytes. */
	if (resctrl_mon_feature_exists(L3_MON, MBM_LOCAL_BYTES)) {
		ksft_print_msg("info/%s/mon_features unexpectedly advertises %s\n",
			       L3_MON, MBM_LOCAL_BYTES);
		return -1;
	}
	return 0;
}

static int check_one_mon_domain(const char *dom_dir)
{
	char total_path[PATH_MAX], local_path[PATH_MAX];
	unsigned long long v0, v1;
	struct stat st;

	snprintf(total_path, sizeof(total_path), "%s/%s", dom_dir, MBM_TOTAL_BYTES);
	snprintf(local_path, sizeof(local_path), "%s/%s", dom_dir, MBM_LOCAL_BYTES);

	if (read_u64_file(total_path, &v0))
		return -1;

	if (stat(local_path, &st) == 0) {
		ksft_print_msg("%s unexpectedly exists\n", local_path);
		return -1;
	}

	if (read_u64_file(total_path, &v1))
		return -1;
	if (v1 < v0) {
		ksft_print_msg("%s regressed: %llu -> %llu\n",
			       total_path, v0, v1);
		return -1;
	}
	return 0;
}

static int for_each_l3_mon_domain(int (*cb)(const char *dir))
{
	char dir_path[PATH_MAX];
	struct dirent *de;
	int ret = 0, n = 0;
	DIR *d;

	d = opendir(MON_DATA_DIR);
	if (!d) {
		ksft_print_msg("Cannot open %s: %s\n",
			       MON_DATA_DIR, strerror(errno));
		return -1;
	}

	while ((de = readdir(d))) {
		static const char prefix[] = "mon_L3_";

		if (strncmp(de->d_name, prefix, sizeof(prefix) - 1))
			continue;
		snprintf(dir_path, sizeof(dir_path), "%s/%s",
			 MON_DATA_DIR, de->d_name);
		if (cb(dir_path)) {
			ret = -1;
			break;
		}
		n++;
	}
	closedir(d);

	if (!ret && !n) {
		ksft_print_msg("No mon_L3_* domains under %s\n", MON_DATA_DIR);
		return -1;
	}
	return ret;
}

static int cbqri_mbm_run_test(const struct resctrl_test *test,
			      const struct user_params *uparams)
{
	if (check_mon_features())
		return -1;

	if (for_each_l3_mon_domain(check_one_mon_domain))
		return -1;

	ksft_print_msg("Pass: CBQRI mbm_total_bytes interface test\n");
	return 0;
}

static bool cbqri_mbm_feature_check(const struct resctrl_test *test)
{
	/* CBQRI: mbm_total_bytes present, mbm_local_bytes absent. */
	return resctrl_resource_exists("L3") &&
	       resctrl_mon_feature_exists(L3_MON, MBM_TOTAL_BYTES) &&
	       !resctrl_mon_feature_exists(L3_MON, MBM_LOCAL_BYTES);
}

struct resctrl_test cbqri_mbm_test = {
	.name = "CBQRI_MBM",
	.resource = "L3",
	.feature_check = cbqri_mbm_feature_check,
	.run_test = cbqri_mbm_run_test,
};
