// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * The init of the fixture boots. It lists what the kernel unpacked into
 * its root file system, one line per name, to the second serial port and
 * powers the machine off. make-fixtures.py builds it and describes the
 * lines it writes.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#define HARNESS ".harness"

static FILE *out;

/* The first name of every file that has several, by inode number. */
struct first {
	ino_t ino;
	char *path;
};
static struct first *firsts;
static size_t nfirsts;

static void die(const char *what)
{
	if (out) {
		fprintf(out, "! init: %s: %s\n", what, strerror(errno));
		fflush(out);
	}
	sync();
	reboot(RB_POWER_OFF);
	_exit(1);
}

static void escaped(const char *s, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		unsigned char c = s[i];

		if (c <= 0x20 || c >= 0x7f || c == '\\')
			fprintf(out, "\\x%02x", c);
		else
			fputc(c, out);
	}
}

static const char *first_name(const struct stat *st, const char *path)
{
	for (size_t i = 0; i < nfirsts; i++)
		if (firsts[i].ino == st->st_ino)
			return firsts[i].path;
	firsts = realloc(firsts, (nfirsts + 1) * sizeof(*firsts));
	if (!firsts)
		die("realloc");
	firsts[nfirsts].ino = st->st_ino;
	firsts[nfirsts].path = strdup(path);
	nfirsts++;
	return NULL;
}

static void contents(int dirfd, const char *name)
{
	unsigned char buf[65536], head[16];
	unsigned int sum = 0;
	size_t kept = 0;
	ssize_t n;
	int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

	if (fd < 0)
		die("open");
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (ssize_t i = 0; i < n; i++) {
			sum += buf[i];
			if (kept < sizeof(head))
				head[kept++] = buf[i];
		}
	}
	if (n < 0)
		die("read");
	close(fd);
	fprintf(out, " sum=%08x", sum);
	if (kept) {
		fputs(" head=", out);
		for (size_t i = 0; i < kept; i++)
			fprintf(out, "%02x", head[i]);
	}
}

static void entry(int dirfd, const char *name, const char *path, const struct stat *st)
{
	char type;

	switch (st->st_mode & S_IFMT) {
	case S_IFDIR: type = 'd'; break;
	case S_IFREG: type = 'f'; break;
	case S_IFLNK: type = 'l'; break;
	case S_IFCHR: type = 'c'; break;
	case S_IFBLK: type = 'b'; break;
	case S_IFIFO: type = 'p'; break;
	case S_IFSOCK: type = 's'; break;
	default: type = '?'; break;
	}
	escaped(path, strlen(path));
	fprintf(out, " %c", type);
	if (type != 'l')
		fprintf(out, " mode=%04o", (unsigned int)(st->st_mode & 07777));
	fprintf(out, " uid=%u gid=%u mtime=%lld", (unsigned int)st->st_uid, (unsigned int)st->st_gid,
		(long long)st->st_mtim.tv_sec);
	if (type != 'd') {
		const char *first = st->st_nlink > 1 ? first_name(st, path) : NULL;

		fprintf(out, " nlink=%u", (unsigned int)st->st_nlink);
		if (first) {
			fputs(" link=", out);
			escaped(first, strlen(first));
		}
	}
	if (type == 'f') {
		fprintf(out, " size=%lld", (long long)st->st_size);
		contents(dirfd, name);
	} else if (type == 'l') {
		char target[8192];
		ssize_t n = readlinkat(dirfd, name, target, sizeof(target));

		if (n < 0)
			die("readlink");
		fputs(" target=", out);
		escaped(target, n);
	} else if (type == 'c' || type == 'b') {
		fprintf(out, " rdev=%u:%u", major(st->st_rdev), minor(st->st_rdev));
	}
	fputc('\n', out);
}

static int by_bytes(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* A directory right before what is in it, its entries sorted by bytes. */
static void walk(int dirfd, const char *path)
{
	char **names = NULL;
	size_t count = 0;
	struct dirent *de;
	DIR *dir = fdopendir(dup(dirfd));

	if (!dir)
		die("fdopendir");
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (!*path && !strcmp(de->d_name, HARNESS))
			continue;
		names = realloc(names, (count + 1) * sizeof(*names));
		if (!names)
			die("realloc");
		names[count++] = strdup(de->d_name);
	}
	closedir(dir);
	qsort(names, count, sizeof(*names), by_bytes);
	for (size_t i = 0; i < count; i++) {
		struct stat st;
		char *full;

		if (fstatat(dirfd, names[i], &st, AT_SYMLINK_NOFOLLOW) < 0)
			die("fstatat");
		if (asprintf(&full, "%s%s%s", path, *path ? "/" : "", names[i]) < 0)
			die("asprintf");
		entry(dirfd, names[i], full, &st);
		if (S_ISDIR(st.st_mode)) {
			int fd = openat(dirfd, names[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

			if (fd < 0)
				die("openat");
			walk(fd, full);
			close(fd);
		}
		free(full);
		free(names[i]);
	}
	free(names);
}

/* What the kernel said about the archive while unpacking it. */
static void messages(void)
{
	char buf[8192];
	ssize_t n;
	int fd;

	if (mknod("/" HARNESS "/kmsg", S_IFCHR | 0600, makedev(1, 11)) < 0 && errno != EEXIST)
		die("mknod kmsg");
	fd = open("/" HARNESS "/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		die("open kmsg");
	for (;;) {
		char *text, *end;

		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0 && errno == EPIPE)
			continue;
		if (n <= 0)
			break;
		buf[n] = '\0';
		text = strchr(buf, ';');
		if (!text)
			continue;
		text++;
		end = strchr(text, '\n');
		if (end)
			*end = '\0';
		if (strstr(text, "nitramfs"))
			fprintf(out, "! %s\n", text);
	}
	close(fd);
}

int main(void)
{
	struct utsname uts;
	struct termios tio;
	struct stat st;
	int fd, root;

	if (mknod("/" HARNESS "/out", S_IFCHR | 0600, makedev(4, 65)) < 0 && errno != EEXIST)
		_exit(1);
	fd = open("/" HARNESS "/out", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0)
		_exit(1);
	if (!tcgetattr(fd, &tio)) {
		cfmakeraw(&tio);
		tcsetattr(fd, TCSANOW, &tio);
	}
	out = fdopen(fd, "w");
	if (!out)
		_exit(1);
	if (uname(&uts) < 0)
		die("uname");
	fprintf(out, "# %s %s %s\n", uts.release, uts.version, uts.machine);
	messages();
	root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root < 0 || fstat(root, &st) < 0)
		die("open /");
	entry(root, ".", ".", &st);
	walk(root, "");
	fputs("# end\n", out);
	fflush(out);
	tcdrain(fd);
	sync();
	reboot(RB_POWER_OFF);
	return 1;
}
