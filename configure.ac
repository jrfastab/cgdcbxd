AC_INIT([cgdcbx], [1.0.2])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC

AC_SUBST(LIBMNL_CFLAGS)
AC_SUBST(LIBMNL_LIBS)

# Require libcgroup but not new API
PKG_CHECK_MODULES([LIBCGROUP], [libcgroup >= 0.32])
AC_CHECK_LIB(cgroup, cgroup_change_all_cgroups, AC_DEFINE([HAVE_CGROUP_CHANGE_ALL_CGROUPS]))

AC_CHECK_HEADER([libcgroup.h], ,[AC_MSG_ERROR(
[Could not find libcgroup.h. Try installing libcgroup-devel])]
)
AC_CHECK_HEADER([libmnl/libmnl.h], , [AC_MSG_ERROR(
[Could not find libmnl.h. Try installing libmnl-devel])]
)

AC_CHECK_HEADERS([linux/dcbnl.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([sys/file.h])
AC_CHECK_HEADERS([sys/queue.h])
AC_CHECK_HEADERS([sys/select.h])
AC_CHECK_HEADERS([syslog.h])

AC_C_INLINE
AC_FUNC_MALLOC
AC_HEADER_STDBOOL
AC_PREREQ
AC_PROG_INSTALL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T

AC_CONFIG_FILES([Makefile version.h cgdcbxd.spec cgdcbxd.pc])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT
