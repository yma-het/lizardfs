/*
   Copyright 2005-2010 Jakub Kruszona-Zawadzki, Gemius SA, 2013 Skytechnology sp. z o.o..

   This file was part of MooseFS and is part of LizardFS.

   LizardFS is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3.

   LizardFS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LizardFS  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common/platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <fstream>

#include <fuse.h>
#include <fuse/fuse_lowlevel.h>
#include <fuse/fuse_opt.h>

#include "common/crc.h"
#include "common/md5.h"
#include "common/MFSCommunication.h"
#include "common/mfserr.h"
#include "mount/csdb.h"
#include "mount/fuse/mfs_fuse.h"
#include "mount/fuse/mfs_meta_fuse.h"
#include "mount/g_io_limiters.h"
#include "mount/mastercomm.h"
#include "mount/masterproxy.h"
#include "mount/readdata.h"
#include "mount/stats.h"
#include "mount/symlinkcache.h"
#include "mount/writedata.h"

#if defined(LIZARDFS_HAVE_MLOCKALL) && defined(RLIMIT_MEMLOCK)
#  include <sys/mman.h>
#endif

#if defined(MCL_CURRENT) && defined(MCL_FUTURE)
#  define MFS_USE_MEMLOCK
#endif

#define STR_AUX(x) #x
#define STR(x) STR_AUX(x)

#if defined(__APPLE__)
#define DEFAULT_OPTIONS "allow_other,default_permissions,daemon_timeout=600,iosize=65536"
#else
#define DEFAULT_OPTIONS "allow_other,default_permissions"
#endif

static void mfs_fsinit (void *userdata, struct fuse_conn_info *conn);

static struct fuse_lowlevel_ops mfs_meta_oper;

static struct fuse_lowlevel_ops mfs_oper;

static void init_fuse_lowlevel_ops() {
   mfs_meta_oper.init = mfs_fsinit;
   mfs_meta_oper.statfs =   mfs_meta_statfs;
   mfs_meta_oper.lookup =      mfs_meta_lookup;
   mfs_meta_oper.getattr =  mfs_meta_getattr;
   mfs_meta_oper.setattr =  mfs_meta_setattr;
   mfs_meta_oper.unlink =      mfs_meta_unlink;
   mfs_meta_oper.rename =      mfs_meta_rename;
   mfs_meta_oper.opendir =  mfs_meta_opendir;
   mfs_meta_oper.readdir =  mfs_meta_readdir;
   mfs_meta_oper.releasedir =  mfs_meta_releasedir;
   mfs_meta_oper.open =     mfs_meta_open;
   mfs_meta_oper.release =  mfs_meta_release;
   mfs_meta_oper.read =     mfs_meta_read;
   mfs_meta_oper.write =       mfs_meta_write;

   mfs_oper.init           = mfs_fsinit;
   mfs_oper.statfs     = mfs_statfs;
   mfs_oper.lookup     = mfs_lookup;
   mfs_oper.getattr = mfs_getattr;
   mfs_oper.setattr = mfs_setattr;
   mfs_oper.mknod      = mfs_mknod;
   mfs_oper.unlink     = mfs_unlink;
   mfs_oper.mkdir      = mfs_mkdir;
   mfs_oper.rmdir      = mfs_rmdir;
   mfs_oper.symlink = mfs_symlink;
   mfs_oper.readlink   = mfs_readlink;
   mfs_oper.rename     = mfs_rename;
   mfs_oper.link    = mfs_link;
   mfs_oper.opendir = mfs_opendir;
   mfs_oper.readdir = mfs_readdir;
   mfs_oper.releasedir = mfs_releasedir;
   mfs_oper.create     = mfs_create;
   mfs_oper.open    = mfs_open;
   mfs_oper.release = mfs_release;
   mfs_oper.flush      = mfs_flush;
   mfs_oper.fsync      = mfs_fsync;
   mfs_oper.read    = mfs_read;
   mfs_oper.write      = mfs_write;
   mfs_oper.access     = mfs_access;
   mfs_oper.getxattr       = mfs_getxattr;
   mfs_oper.setxattr       = mfs_setxattr;
   mfs_oper.listxattr      = mfs_listxattr;
   mfs_oper.removexattr    = mfs_removexattr;
}

struct mfsopts {
	char *masterhost;
	char *masterport;
	char *bindhost;
	char *subfolder;
	char *password;
	char *md5pass;
	unsigned nofile;
	signed nice;
#ifdef MFS_USE_MEMLOCK
	int memlock;
#endif
	int nostdmountoptions;
	int meta;
	int debug;
	int delayedinit;
	int acl;
	int mkdircopysgid;
	char *sugidclearmodestr;
	SugidClearMode sugidclearmode;
	char *cachemode;
	int cachefiles;
	int keepcache;
	int passwordask;
	int donotrememberpassword;
	unsigned writecachesize;
	unsigned ioretries;
	unsigned aclcachesize;
	double attrcacheto;
	double entrycacheto;
	double direntrycacheto;
	double aclcacheto;
	unsigned reportreservedperiod;
	char *iolimits;
};

static struct mfsopts mfsopts;
static char *defaultmountpoint = NULL;

static int custom_cfg;

enum {
	KEY_CFGFILE,
	KEY_META,
	KEY_HOST,
	KEY_PORT,
	KEY_BIND,
	KEY_PATH,
	KEY_PASSWORDASK,
	KEY_NOSTDMOUNTOPTIONS,
	KEY_HELP,
	KEY_VERSION
};

#define MFS_OPT(t, p, v) { t, offsetof(struct mfsopts, p), v }

static struct fuse_opt mfs_opts_stage1[] = {
	FUSE_OPT_KEY("mfscfgfile=",    KEY_CFGFILE),
	FUSE_OPT_KEY("-c ",            KEY_CFGFILE),
	FUSE_OPT_END
};

static struct fuse_opt mfs_opts_stage2[] = {
	MFS_OPT("mfsmaster=%s", masterhost, 0),
	MFS_OPT("mfsport=%s", masterport, 0),
	MFS_OPT("mfsbind=%s", bindhost, 0),
	MFS_OPT("mfssubfolder=%s", subfolder, 0),
	MFS_OPT("mfspassword=%s", password, 0),
	MFS_OPT("mfsmd5pass=%s", md5pass, 0),
	MFS_OPT("mfsrlimitnofile=%u", nofile, 0),
	MFS_OPT("mfsnice=%d", nice, 0),
#ifdef MFS_USE_MEMLOCK
	MFS_OPT("mfsmemlock", memlock, 1),
#endif
	MFS_OPT("mfswritecachesize=%u", writecachesize, 0),
	MFS_OPT("mfsaclcachesize=%u", aclcachesize, 0),
	MFS_OPT("mfsioretries=%u", ioretries, 0),
	MFS_OPT("mfsdebug", debug, 1),
	MFS_OPT("mfsmeta", meta, 1),
	MFS_OPT("mfsdelayedinit", delayedinit, 1),
	MFS_OPT("mfsacl", acl, 1),
	MFS_OPT("mfsdonotrememberpassword", donotrememberpassword, 1),
	MFS_OPT("mfscachefiles", cachefiles, 1),
	MFS_OPT("mfscachemode=%s", cachemode, 0),
	MFS_OPT("mfsmkdircopysgid=%u", mkdircopysgid, 0),
	MFS_OPT("mfssugidclearmode=%s", sugidclearmodestr, 0),
	MFS_OPT("mfsattrcacheto=%lf", attrcacheto, 0),
	MFS_OPT("mfsentrycacheto=%lf", entrycacheto, 0),
	MFS_OPT("mfsdirentrycacheto=%lf", direntrycacheto, 0),
	MFS_OPT("mfsaclcacheto=%lf", aclcacheto, 0),
	MFS_OPT("mfsreportreservedperiod=%u", reportreservedperiod, 0),
	MFS_OPT("mfsiolimits=%s", iolimits, 0),

	FUSE_OPT_KEY("-m",             KEY_META),
	FUSE_OPT_KEY("--meta",         KEY_META),
	FUSE_OPT_KEY("-H ",            KEY_HOST),
	FUSE_OPT_KEY("-P ",            KEY_PORT),
	FUSE_OPT_KEY("-B ",            KEY_BIND),
	FUSE_OPT_KEY("-S ",            KEY_PATH),
	FUSE_OPT_KEY("-p",             KEY_PASSWORDASK),
	FUSE_OPT_KEY("--password",     KEY_PASSWORDASK),
	FUSE_OPT_KEY("-n",             KEY_NOSTDMOUNTOPTIONS),
	FUSE_OPT_KEY("--nostdopts",    KEY_NOSTDMOUNTOPTIONS),
	FUSE_OPT_KEY("-V",             KEY_VERSION),
	FUSE_OPT_KEY("--version",      KEY_VERSION),
	FUSE_OPT_KEY("-h",             KEY_HELP),
	FUSE_OPT_KEY("--help",         KEY_HELP),
	FUSE_OPT_END
};

static void usage(const char *progname) {
	fprintf(stderr,
"usage: %s mountpoint [options]\n"
"\n", progname);
	fprintf(stderr,
"general options:\n"
"    -o opt,[opt...]         mount options\n"
"    -h   --help             print help\n"
"    -V   --version          print version\n"
"\n");
	fprintf(stderr,
"MFS options:\n"
"    -c CFGFILE                  equivalent to '-o mfscfgfile=CFGFILE'\n"
"    -m   --meta                 equivalent to '-o mfsmeta'\n"
"    -H HOST                     equivalent to '-o mfsmaster=HOST'\n"
"    -P PORT                     equivalent to '-o mfsport=PORT'\n"
"    -B IP                       equivalent to '-o mfsbind=IP'\n"
"    -S PATH                     equivalent to '-o mfssubfolder=PATH'\n"
"    -p   --password             similar to '-o mfspassword=PASSWORD', but show prompt and ask user for password\n"
"    -n   --nostdopts            do not add standard LizardFS mount options: '-o " DEFAULT_OPTIONS ",fsname=MFS'\n"
"    -o mfscfgfile=CFGFILE       load some mount options from external file (if not specified then use default file: " ETC_PATH "/mfsmount.cfg)\n"
"    -o mfsdebug                 print some debugging information\n"
"    -o mfsmeta                  mount meta filesystem (trash etc.)\n"
"    -o mfsdelayedinit           connection with master is done in background - with this option mount can be run without network (good for being run from fstab / init scripts etc.)\n"
"    -o mfsacl                   enable ACL support (disabled by default)\n"
#ifdef __linux__
"    -o mfsmkdircopysgid=N       sgid bit should be copied during mkdir operation (default: 1)\n"
#else
"    -o mfsmkdircopysgid=N       sgid bit should be copied during mkdir operation (default: 0)\n"
#endif
#if defined(DEFAULT_SUGID_CLEAR_MODE_EXT)
"    -o mfssugidclearmode=SMODE  set sugid clear mode (see below ; default: EXT)\n"
#elif defined(DEFAULT_SUGID_CLEAR_MODE_BSD)
"    -o mfssugidclearmode=SMODE  set sugid clear mode (see below ; default: BSD)\n"
#elif defined(DEFAULT_SUGID_CLEAR_MODE_OSX)
"    -o mfssugidclearmode=SMODE  set sugid clear mode (see below ; default: OSX)\n"
#else
"    -o mfssugidclearmode=SMODE  set sugid clear mode (see below ; default: NEVER)\n"
#endif
"    -o mfscachemode=CMODE       set cache mode (see below ; default: AUTO)\n"
"    -o mfscachefiles            (deprecated) equivalent to '-o mfscachemode=YES'\n"
"    -o mfsattrcacheto=SEC       set attributes cache timeout in seconds (default: 1.0)\n"
"    -o mfsentrycacheto=SEC      set file entry cache timeout in seconds (default: 0.0)\n"
"    -o mfsdirentrycacheto=SEC   set directory entry cache timeout in seconds (default: 1.0)\n"
"    -o mfsaclcacheto=SEC        set ACL cache timeout in seconds (default: 1.0)\n"
"    -o mfsreportreservedperiod=SEC set reporting reserved inodes interval in seconds (default: 60)\n"
"    -o mfsrlimitnofile=N        on startup mfsmount tries to change number of descriptors it can simultaneously open (default: 100000)\n"
"    -o mfsnice=N                on startup mfsmount tries to change his 'nice' value (default: -19)\n"
#ifdef MFS_USE_MEMLOCK
"    -o mfsmemlock               try to lock memory\n"
#endif
"    -o mfswritecachesize=N      define size of write cache in MiB (default: 128)\n"
"    -o mfsaclcachesize=N        define ACL cache size in number of entries (0: no cache; default: 1000)\n"
"    -o mfsioretries=N           define number of retries before I/O error is returned (default: 30)\n"
"    -o mfsmaster=HOST           define mfsmaster location (default: mfsmaster)\n"
"    -o mfsport=PORT             define mfsmaster port number (default: 9421)\n"
"    -o mfsbind=IP               define source ip address for connections (default: NOT DEFINED - chosen automatically by OS)\n"
"    -o mfssubfolder=PATH        define subfolder to mount as root (default: /)\n"
"    -o mfspassword=PASSWORD     authenticate to mfsmaster with password\n"
"    -o mfsmd5pass=MD5           authenticate to mfsmaster using directly given md5 (only if mfspassword is not defined)\n"
"    -o mfsdonotrememberpassword do not remember password in memory - more secure, but when session is lost then new session is created without password\n"
"    -o mfsiolimits=FILE         define I/O limits configuration file\n"
"\n");
	fprintf(stderr,
"CMODE can be set to:\n"
"    NO,NONE or NEVER            never allow files data to be kept in cache (safest but can reduce efficiency)\n"
"    YES or ALWAYS               always allow files data to be kept in cache (dangerous)\n"
"    AUTO                        file cache is managed by mfsmaster automatically (should be very safe and efficient)\n"
"\n");
	fprintf(stderr,
"SMODE can be set to:\n"
"    NEVER                       LizardFS will not change suid and sgid bit on chown\n"
"    ALWAYS                      clear suid and sgid on every chown - safest operation\n"
"    OSX                         standard behavior in OS X and Solaris (chown made by unprivileged user clear suid and sgid)\n"
"    BSD                         standard behavior in *BSD systems (like in OSX, but only when something is really changed)\n"
"    EXT                         standard behavior in most file systems on Linux (directories not changed, others: suid cleared always, sgid only when group exec bit is set)\n"
"    XFS                         standard behavior in XFS on Linux (like EXT but directories are changed by unprivileged users)\n"
"SMODE extra info:\n"
"    btrfs,ext2,ext3,ext4,hfs[+],jfs,ntfs and reiserfs on Linux work as 'EXT'.\n"
"    Only xfs on Linux works a little different. Beware that there is a strange\n"
"    operation - chown(-1,-1) which is usually converted by a kernel into something\n"
"    like 'chmod ug-s', and therefore can't be controlled by MFS as 'chown'\n"
"\n");
}

static void mfs_opt_parse_cfg_file(const char *filename,int optional,struct fuse_args *outargs) {
	FILE *fd;
	char lbuff[1000],*p;

	fd = fopen(filename,"r");
	if (fd==NULL) {
		if (optional==0) {
			fprintf(stderr,"can't open cfg file: %s\n",filename);
			abort();
		}
		return;
	}
	custom_cfg = 1;
	while (fgets(lbuff,999,fd)) {
		if (lbuff[0]!='#' && lbuff[0]!=';') {
			lbuff[999]=0;
			for (p = lbuff ; *p ; p++) {
				if (*p=='\r' || *p=='\n') {
					*p=0;
					break;
				}
			}
			p--;
			while (p>=lbuff && (*p==' ' || *p=='\t')) {
				*p=0;
				p--;
			}
			p = lbuff;
			while (*p==' ' || *p=='\t') {
				p++;
			}
			if (*p) {
				if (*p=='-') {
					fuse_opt_add_arg(outargs,p);
				} else if (*p=='/') {
					if (defaultmountpoint) {
						free(defaultmountpoint);
					}
					defaultmountpoint = strdup(p);
				} else {
					fuse_opt_add_arg(outargs,"-o");
					fuse_opt_add_arg(outargs,p);
				}
			}
		}
	}
	fclose(fd);
}

static int mfs_opt_proc_stage1(void *data, const char *arg, int key, struct fuse_args *outargs) {
	struct fuse_args *defargs = (struct fuse_args*)data;
	(void)outargs;

	if (key==KEY_CFGFILE) {
		if (memcmp(arg,"mfscfgfile=",11)==0) {
			mfs_opt_parse_cfg_file(arg+11,0,defargs);
		} else if (arg[0]=='-' && arg[1]=='c') {
			mfs_opt_parse_cfg_file(arg+2,0,defargs);
		}
		return 0;
	}
	return 1;
}

// return value:
//   0 - discard this arg
//   1 - keep this arg for future processing
static int mfs_opt_proc_stage2(void *data, const char *arg, int key, struct fuse_args *outargs) {
	(void)data;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
		return 1;
	case FUSE_OPT_KEY_NONOPT:
		return 1;
	case KEY_HOST:
		if (mfsopts.masterhost!=NULL) {
			free(mfsopts.masterhost);
		}
		mfsopts.masterhost = strdup(arg+2);
		return 0;
	case KEY_PORT:
		if (mfsopts.masterport!=NULL) {
			free(mfsopts.masterport);
		}
		mfsopts.masterport = strdup(arg+2);
		return 0;
	case KEY_BIND:
		if (mfsopts.bindhost!=NULL) {
			free(mfsopts.bindhost);
		}
		mfsopts.bindhost = strdup(arg+2);
		return 0;
	case KEY_PATH:
		if (mfsopts.subfolder!=NULL) {
			free(mfsopts.subfolder);
		}
		mfsopts.subfolder = strdup(arg+2);
		return 0;
	case KEY_PASSWORDASK:
		mfsopts.passwordask = 1;
		return 0;
	case KEY_META:
		mfsopts.meta = 1;
		return 0;
	case KEY_NOSTDMOUNTOPTIONS:
		mfsopts.nostdmountoptions = 1;
		return 0;
	case KEY_VERSION:
		fprintf(stderr, "LizardFS version %s\n", LIZARDFS_PACKAGE_VERSION);
		{
			struct fuse_args helpargs = FUSE_ARGS_INIT(0, NULL);

			fuse_opt_add_arg(&helpargs,outargs->argv[0]);
			fuse_opt_add_arg(&helpargs,"--version");
			fuse_parse_cmdline(&helpargs,NULL,NULL,NULL);
			fuse_unmount(NULL, fuse_mount(NULL, &helpargs));
		}
		exit(0);
	case KEY_HELP:
		usage(outargs->argv[0]);
		{
			struct fuse_args helpargs = FUSE_ARGS_INIT(0, NULL);

			fuse_opt_add_arg(&helpargs,outargs->argv[0]);
			fuse_opt_add_arg(&helpargs,"-ho");
			fuse_parse_cmdline(&helpargs,NULL,NULL,NULL);
			fuse_unmount(NULL, fuse_mount(NULL, &helpargs));
		}
		exit(1);
	default:
		fprintf(stderr, "internal error\n");
		abort();
	}
}

static void mfs_fsinit (void *userdata, struct fuse_conn_info *conn) {
	conn->want |= FUSE_CAP_DONT_MASK;

	int *piped = (int*)userdata;
	if (piped[1]>=0) {
		char s = 0;
		if (write(piped[1],&s,1)!=1) {
			syslog(LOG_ERR,"pipe write error: %s",strerr(errno));
		}
		close(piped[1]);
	}
}

int mainloop(struct fuse_args *args,const char* mp,int mt,int fg) {
	struct fuse_session *se;
	struct fuse_chan *ch;
	struct rlimit rls;
	int piped[2];
	char s;
	int err;
	int i;
	md5ctx ctx;
	uint8_t md5pass[16];

	if (mfsopts.passwordask && mfsopts.password==NULL && mfsopts.md5pass==NULL) {
		mfsopts.password = getpass("MFS Password:");
	}
	if (mfsopts.password) {
		md5_init(&ctx);
		md5_update(&ctx,(uint8_t*)(mfsopts.password),strlen(mfsopts.password));
		md5_final(md5pass,&ctx);
		memset(mfsopts.password,0,strlen(mfsopts.password));
	} else if (mfsopts.md5pass) {
		uint8_t *p = (uint8_t*)(mfsopts.md5pass);
		for (i=0 ; i<16 ; i++) {
			if (*p>='0' && *p<='9') {
				md5pass[i]=(*p-'0')<<4;
			} else if (*p>='a' && *p<='f') {
				md5pass[i]=(*p-'a'+10)<<4;
			} else if (*p>='A' && *p<='F') {
				md5pass[i]=(*p-'A'+10)<<4;
			} else {
				fprintf(stderr,"bad md5 definition (md5 should be given as 32 hex digits)\n");
				return 1;
			}
			p++;
			if (*p>='0' && *p<='9') {
				md5pass[i]+=(*p-'0');
			} else if (*p>='a' && *p<='f') {
				md5pass[i]+=(*p-'a'+10);
			} else if (*p>='A' && *p<='F') {
				md5pass[i]+=(*p-'A'+10);
			} else {
				fprintf(stderr,"bad md5 definition (md5 should be given as 32 hex digits)\n");
				return 1;
			}
			p++;
		}
		if (*p) {
			fprintf(stderr,"bad md5 definition (md5 should be given as 32 hex digits)\n");
			return 1;
		}
		memset(mfsopts.md5pass,0,strlen(mfsopts.md5pass));
	}

	if (mfsopts.delayedinit) {
		fs_init_master_connection(mfsopts.bindhost, mfsopts.masterhost, mfsopts.masterport,
				mfsopts.meta, mp, mfsopts.subfolder,
				(mfsopts.password || mfsopts.md5pass) ? md5pass : NULL,
				mfsopts.donotrememberpassword, 1, mfsopts.ioretries, mfsopts.reportreservedperiod);
	} else {
		if (fs_init_master_connection(mfsopts.bindhost, mfsopts.masterhost, mfsopts.masterport,
					mfsopts.meta, mp, mfsopts.subfolder,
					(mfsopts.password || mfsopts.md5pass) ? md5pass : NULL,
					mfsopts.donotrememberpassword, 0, mfsopts.ioretries,
					mfsopts.reportreservedperiod) < 0) {
			return 1;
		}
	}
	memset(md5pass,0,16);

	if (fg==0) {
		openlog(STR(APPNAME), LOG_PID | LOG_NDELAY , LOG_DAEMON);
	} else {
#if defined(LOG_PERROR)
		openlog(STR(APPNAME), LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_USER);
#else
		openlog(STR(APPNAME), LOG_PID | LOG_NDELAY, LOG_USER);
#endif
	}

	rls.rlim_cur = mfsopts.nofile;
	rls.rlim_max = mfsopts.nofile;
	setrlimit(RLIMIT_NOFILE,&rls);

	setpriority(PRIO_PROCESS,getpid(),mfsopts.nice);
#ifdef MFS_USE_MEMLOCK
	if (mfsopts.memlock) {
		rls.rlim_cur = RLIM_INFINITY;
		rls.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_MEMLOCK,&rls)<0) {
			mfsopts.memlock=0;
		}
	}
#endif

	piped[0] = piped[1] = -1;
	if (fg==0) {
		if (pipe(piped)<0) {
			fprintf(stderr,"pipe error\n");
			return 1;
		}
		err = fork();
		if (err<0) {
			fprintf(stderr,"fork error\n");
			return 1;
		} else if (err>0) {
			close(piped[1]);
			err = read(piped[0],&s,1);
			if (err==0) {
				s=1;
			}
			return s;
		}
		close(piped[0]);
		s=1;
	}


#ifdef MFS_USE_MEMLOCK
	if (mfsopts.memlock) {
		if (mlockall(MCL_CURRENT|MCL_FUTURE)==0) {
			syslog(LOG_NOTICE,"process memory was successfully locked in RAM");
		}
	}
#endif

	symlink_cache_init();
	if (mfsopts.meta == 0) {
		// initialize the global IO limiter before starting mastercomm threads
		gGlobalIoLimiter();
	}
	fs_init_threads(mfsopts.ioretries);
	masterproxy_init();

	if (mfsopts.meta==0) {
		try {
			IoLimitsConfigLoader loader;
			if (mfsopts.iolimits) {
				loader.load(std::ifstream(mfsopts.iolimits));
			}
			// initialize the local limiter before loading configuration
			gLocalIoLimiter();
			gMountLimiter().loadConfiguration(loader);
		} catch (Exception& ex) {
			fprintf(stderr, "Can't initialize I/O limiting: %s", ex.what());
			masterproxy_term();
			fs_term();
			symlink_cache_term();
			return 1;
		}
		csdb_init();
		read_data_init(mfsopts.ioretries);
		write_data_init(mfsopts.writecachesize*1024*1024,mfsopts.ioretries);
	}

	ch = fuse_mount(mp, args);
	if (ch==NULL) {
		fprintf(stderr,"error in fuse_mount\n");
		if (piped[1]>=0) {
			if (write(piped[1],&s,1)!=1) {
				fprintf(stderr,"pipe write error\n");
			}
			close(piped[1]);
		}
		if (mfsopts.meta==0) {
			write_data_term();
			read_data_term();
			csdb_term();
		}
		masterproxy_term();
		fs_term();
		symlink_cache_term();
		return 1;
	}

	if (mfsopts.meta) {
		mfs_meta_init(mfsopts.debug,mfsopts.entrycacheto,mfsopts.attrcacheto);
		se = fuse_lowlevel_new(args, &mfs_meta_oper, sizeof(mfs_meta_oper), (void*)piped);
	} else {
		mfs_init(mfsopts.debug, mfsopts.keepcache, mfsopts.direntrycacheto, mfsopts.entrycacheto,
				mfsopts.attrcacheto, mfsopts.mkdircopysgid, mfsopts.sugidclearmode, mfsopts.acl,
				mfsopts.aclcacheto, mfsopts.aclcachesize);
		se = fuse_lowlevel_new(args, &mfs_oper, sizeof(mfs_oper), (void*)piped);
	}
	if (se==NULL) {
		fuse_unmount(mp,ch);
		fprintf(stderr,"error in fuse_lowlevel_new\n");
		usleep(100000); // time for print other error messages by FUSE
		if (piped[1]>=0) {
			if (write(piped[1],&s,1)!=1) {
				fprintf(stderr,"pipe write error\n");
			}
			close(piped[1]);
		}
		if (mfsopts.meta==0) {
			write_data_term();
			read_data_term();
			csdb_term();
		}
		masterproxy_term();
		fs_term();
		symlink_cache_term();
		return 1;
	}

	fuse_session_add_chan(se, ch);

	if (fuse_set_signal_handlers(se)<0) {
		fprintf(stderr,"error in fuse_set_signal_handlers\n");
		fuse_session_remove_chan(ch);
		fuse_session_destroy(se);
		fuse_unmount(mp,ch);
		if (piped[1]>=0) {
			if (write(piped[1],&s,1)!=1) {
				fprintf(stderr,"pipe write error\n");
			}
			close(piped[1]);
		}
		if (mfsopts.meta==0) {
			write_data_term();
			read_data_term();
			csdb_term();
		}
		masterproxy_term();
		fs_term();
		symlink_cache_term();
		return 1;
	}

	if (mfsopts.debug==0 && fg==0) {
		setsid();
		setpgid(0,getpid());
		if ((i = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(i, STDIN_FILENO);
			(void)dup2(i, STDOUT_FILENO);
			(void)dup2(i, STDERR_FILENO);
			if (i>2) close (i);
		}
	}

	if (mt) {
		err = fuse_session_loop_mt(se);
	} else {
		err = fuse_session_loop(se);
	}
	if (err) {
		if (piped[1]>=0) {
			if (write(piped[1],&s,1)!=1) {
				syslog(LOG_ERR,"pipe write error: %s",strerr(errno));
			}
			close(piped[1]);
		}
	}
	fuse_remove_signal_handlers(se);
	fuse_session_remove_chan(ch);
	fuse_session_destroy(se);
	fuse_unmount(mp,ch);
	if (mfsopts.meta==0) {
		write_data_term();
		read_data_term();
		csdb_term();
	}
	masterproxy_term();
	fs_term();
	symlink_cache_term();
	return err ? 1 : 0;
}

#if FUSE_VERSION == 25
static int fuse_opt_insert_arg(struct fuse_args *args, int pos, const char *arg) {
	assert(pos <= args->argc);
	if (fuse_opt_add_arg(args, arg) == -1) {
		return -1;
	}
	if (pos != args->argc - 1) {
		char *newarg = args->argv[args->argc - 1];
		memmove(&args->argv[pos + 1], &args->argv[pos], sizeof(char *) * (args->argc - pos - 1));
		args->argv[pos] = newarg;
	}
	return 0;
}
#endif

static unsigned int strncpy_remove_commas(char *dstbuff, unsigned int dstsize,char *src) {
	char c;
	unsigned int l;
	l=0;
	while ((c=*src++) && l+1<dstsize) {
		if (c!=',') {
			*dstbuff++ = c;
			l++;
		}
	}
	*dstbuff=0;
	return l;
}

#if LIZARDFS_HAVE_FUSE_VERSION
static unsigned int strncpy_escape_commas(char *dstbuff, unsigned int dstsize,char *src) {
	char c;
	unsigned int l;
	l=0;
	while ((c=*src++) && l+1<dstsize) {
		if (c!=',' && c!='\\') {
			*dstbuff++ = c;
			l++;
		} else {
			if (l+2<dstsize) {
				*dstbuff++ = '\\';
				*dstbuff++ = c;
				l+=2;
			} else {
				*dstbuff=0;
				return l;
			}
		}
	}
	*dstbuff=0;
	return l;
}
#endif

void make_fsname(struct fuse_args *args) {
	char fsnamearg[256];
	unsigned int l;
#if LIZARDFS_HAVE_FUSE_VERSION
	int libver;
	libver = fuse_version();
	if (libver >= 27) {
		l = snprintf(fsnamearg,256,"-osubtype=mfs%s,fsname=",(mfsopts.meta)?"meta":"");
		if (libver >= 28) {
			l += strncpy_escape_commas(fsnamearg+l,256-l,mfsopts.masterhost);
			if (l<255) {
				fsnamearg[l++]=':';
			}
			l += strncpy_escape_commas(fsnamearg+l,256-l,mfsopts.masterport);
			if (mfsopts.subfolder[0]!='/') {
				if (l<255) {
					fsnamearg[l++]='/';
				}
			}
			if (mfsopts.subfolder[0]!='/' && mfsopts.subfolder[1]!=0) {
				l += strncpy_escape_commas(fsnamearg+l,256-l,mfsopts.subfolder);
			}
			if (l>255) {
				l=255;
			}
			fsnamearg[l]=0;
		} else {
			l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.masterhost);
			if (l<255) {
				fsnamearg[l++]=':';
			}
			l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.masterport);
			if (mfsopts.subfolder[0]!='/') {
				if (l<255) {
					fsnamearg[l++]='/';
				}
			}
			if (mfsopts.subfolder[0]!='/' && mfsopts.subfolder[1]!=0) {
				l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.subfolder);
			}
			if (l>255) {
				l=255;
			}
			fsnamearg[l]=0;
		}
	} else {
#else
		l = snprintf(fsnamearg,256,"-ofsname=mfs%s#",(mfsopts.meta)?"meta":"");
		l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.masterhost);
		if (l<255) {
			fsnamearg[l++]=':';
		}
		l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.masterport);
		if (mfsopts.subfolder[0]!='/') {
			if (l<255) {
				fsnamearg[l++]='/';
			}
		}
		if (mfsopts.subfolder[0]!='/' && mfsopts.subfolder[1]!=0) {
			l += strncpy_remove_commas(fsnamearg+l,256-l,mfsopts.subfolder);
		}
		if (l>255) {
			l=255;
		}
		fsnamearg[l]=0;
#endif
#if LIZARDFS_HAVE_FUSE_VERSION
	}
#endif
	fuse_opt_insert_arg(args, 1, fsnamearg);
}

int main(int argc, char *argv[]) {
	int res;
	int mt,fg;
	char *mountpoint;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_args defaultargs = FUSE_ARGS_INIT(0, NULL);

	strerr_init();
	mycrc32_init();

   init_fuse_lowlevel_ops();

	mfsopts.masterhost = NULL;
	mfsopts.masterport = NULL;
	mfsopts.bindhost = NULL;
	mfsopts.subfolder = NULL;
	mfsopts.password = NULL;
	mfsopts.md5pass = NULL;
	mfsopts.nofile = 0;
	mfsopts.nice = -19;
#ifdef MFS_USE_MEMLOCK
	mfsopts.memlock = 0;
#endif
	mfsopts.nostdmountoptions = 0;
	mfsopts.meta = 0;
	mfsopts.debug = 0;
	mfsopts.delayedinit = 0;
	mfsopts.acl = 0;
#ifdef __linux__
	mfsopts.mkdircopysgid = 1;
#else
	mfsopts.mkdircopysgid = 0;
#endif
	mfsopts.sugidclearmodestr = NULL;
	mfsopts.donotrememberpassword = 0;
	mfsopts.cachefiles = 0;
	mfsopts.cachemode = NULL;
	mfsopts.writecachesize = 0;
	mfsopts.aclcachesize = 1000;
	mfsopts.ioretries = 30;
	mfsopts.passwordask = 0;
	mfsopts.attrcacheto = 1.0;
	mfsopts.entrycacheto = 0.0;
	mfsopts.direntrycacheto = 1.0;
	mfsopts.aclcacheto = 1.0;
	mfsopts.reportreservedperiod = 60;

	custom_cfg = 0;

	fuse_opt_add_arg(&defaultargs,"fakeappname");

	if (fuse_opt_parse(&args, &defaultargs, mfs_opts_stage1, mfs_opt_proc_stage1)<0) {
		exit(1);
	}

	if (custom_cfg==0) {
		mfs_opt_parse_cfg_file(ETC_PATH "/mfsmount.cfg",1,&defaultargs);
	}

	if (fuse_opt_parse(&defaultargs, &mfsopts, mfs_opts_stage2, mfs_opt_proc_stage2)<0) {
		exit(1);
	}

	if (fuse_opt_parse(&args, &mfsopts, mfs_opts_stage2, mfs_opt_proc_stage2)<0) {
		exit(1);
	}

	if (mfsopts.cachemode!=NULL && mfsopts.cachefiles) {
		fprintf(stderr,"mfscachemode and mfscachefiles options are exclusive - use only mfscachemode\nsee: %s -h for help\n",argv[0]);
		return 1;
	}

	if (mfsopts.cachemode==NULL) {
		mfsopts.keepcache=(mfsopts.cachefiles)?1:0;
	} else if (strcasecmp(mfsopts.cachemode,"AUTO")==0) {
		mfsopts.keepcache=0;
	} else if (strcasecmp(mfsopts.cachemode,"YES")==0 || strcasecmp(mfsopts.cachemode,"ALWAYS")==0) {
		mfsopts.keepcache=1;
	} else if (strcasecmp(mfsopts.cachemode,"NO")==0 || strcasecmp(mfsopts.cachemode,"NONE")==0 || strcasecmp(mfsopts.cachemode,"NEVER")==0) {
		mfsopts.keepcache=2;
	} else {
		fprintf(stderr,"unrecognized cachemode option\nsee: %s -h for help\n",argv[0]);
		return 1;
	}
	if (mfsopts.sugidclearmodestr==NULL) {
#if defined(DEFAULT_SUGID_CLEAR_MODE_EXT)
		mfsopts.sugidclearmode = SugidClearMode::kExt;
#elif defined(DEFAULT_SUGID_CLEAR_MODE_BSD)
		mfsopts.sugidclearmode = SugidClearMode::kBsd;
#elif defined(DEFAULT_SUGID_CLEAR_MODE_OSX)
		mfsopts.sugidclearmode = SugidClearMode::kOsx;
#else
		mfsopts.sugidclearmode = SugidClearMode::kNever;
#endif
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"NEVER")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kNever;
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"ALWAYS")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kAlways;
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"OSX")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kOsx;
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"BSD")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kBsd;
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"EXT")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kExt;
	} else if (strcasecmp(mfsopts.sugidclearmodestr,"XFS")==0) {
		mfsopts.sugidclearmode = SugidClearMode::kXfs;
	} else {
		fprintf(stderr,"unrecognized sugidclearmode option\nsee: %s -h for help\n",argv[0]);
		return 1;
	}
	if (mfsopts.masterhost==NULL) {
		mfsopts.masterhost = strdup("mfsmaster");
	}
	if (mfsopts.masterport==NULL) {
		mfsopts.masterport = strdup("9421");
	}
	if (mfsopts.subfolder==NULL) {
		mfsopts.subfolder = strdup("/");
	}
	if (mfsopts.nofile==0) {
		mfsopts.nofile=100000;
	}
	if (mfsopts.writecachesize==0) {
		mfsopts.writecachesize=128;
	}
	if (mfsopts.writecachesize<16) {
		fprintf(stderr,"write cache size too low (%u MiB) - increased to 16 MiB\n",mfsopts.writecachesize);
		mfsopts.writecachesize=16;
	}
	if (mfsopts.writecachesize>2048) {
		fprintf(stderr,"write cache size too big (%u MiB) - decreased to 2048 MiB\n",mfsopts.writecachesize);
		mfsopts.writecachesize=2048;
	}
	if (mfsopts.aclcachesize > 1000 * 1000) {
		fprintf(stderr,"acl cache size too big (%u) - decreased to 1000000\n",mfsopts.aclcachesize);
		mfsopts.aclcachesize=1000 * 1000;
	}

	if (mfsopts.nostdmountoptions==0) {
		fuse_opt_add_arg(&args, "-o" DEFAULT_OPTIONS);
	}


	make_fsname(&args);

	if (fuse_parse_cmdline(&args,&mountpoint,&mt,&fg)<0) {
		fprintf(stderr,"see: %s -h for help\n",argv[0]);
		return 1;
	}

	if (!mountpoint) {
		if (defaultmountpoint) {
			mountpoint = defaultmountpoint;
		} else {
			fprintf(stderr,"no mount point\nsee: %s -h for help\n",argv[0]);
			return 1;
		}
	}

	res = mainloop(&args,mountpoint,mt,fg);
	fuse_opt_free_args(&args);
	fuse_opt_free_args(&defaultargs);
	free(mfsopts.masterhost);
	free(mfsopts.masterport);
	if (mfsopts.bindhost) {
		free(mfsopts.bindhost);
	}
	free(mfsopts.subfolder);
	if (defaultmountpoint && defaultmountpoint != mountpoint) {
		free(defaultmountpoint);
	}
	if (mfsopts.iolimits) {
		free(mfsopts.iolimits);
	}
	free(mountpoint);
	stats_term();
	strerr_term();
	return res;
}
