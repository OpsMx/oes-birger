#!/bin/sh

#
# Build a Docker image with a set of tags based on the
# Git tag.
#
# For a Git tag of 'v1.2.3' we will tag the image
# with ':v1.2.3', 'v1.2', and 'v1'.  Note that this
# means we cannot safely build v1.2.3, v1.3.0, and
# then build v1.2.4 in that order because 'v1' will
# become older (move fo v1.3.0 to v1.2.4)
#
# TODO:  Add a check to see if we should only
# trickle up to less specific versions if we are
# the latest on that path.
#

prefix=$1 ; shift
if [ -z "$prefix" ] ; then
    echo "Expected first argument to be a common image prefix"
    exit 1
fi

now=$1 ; shift
if [ -z "$now" ] ; then
    echo "Expected second argument to be a timestamp as a default tag"
    exit 1
fi

if [ ! -n "$GIT_BRANCH" ] ; then
    echo "--tag ${prefix}:latest --tag ${prefix}:${now}"
    exit 1
fi

tag=`echo "$GIT_BRANCH" |sed 's,/, ,g' | awk '{ print $NF}'`
parts=`echo "$tag" | sed 's/\\./ /g'`

imageTags='latest-release'
prev=''
for i in $parts ; do
  current="$i"
  if [ -n "$prev" ] ; then
    current="$prev.$current"
  fi
  prev="$current"
  imageTags="$imageTags $current"
done

argline=''
for i in $imageTags ; do
    argline="$argline --tag ${prefix}:$i"
done
echo $argline
