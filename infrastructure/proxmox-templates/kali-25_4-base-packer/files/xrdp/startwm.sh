#!/bin/sh
# Launch xfce4 for xrdp sessions.
#
# The stock /etc/xrdp/startwm.sh runs Xsession, which on a Kali box with no
# display manager configured finds no session to start and leaves the client
# looking at a blank blue screen that never resolves. Naming the session
# explicitly is what turns an xrdp connection into a desktop.
if test -r /etc/profile; then . /etc/profile; fi
if test -r ~/.profile; then . ~/.profile; fi

export XDG_SESSION_DESKTOP=xfce
export XDG_CURRENT_DESKTOP=XFCE

exec /usr/bin/startxfce4
