#! /usr/bin/perl
# Copyright (c) 2006, 2007 Manoj Srivastava <srivasta@debian.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

require 5.002;
package IkiWiki::Plugin::calendar;

use warnings;
use strict;
use IkiWiki 3.00;
use Time::Local;
use POSIX;

my $time=time;
my @now=localtime($time);

sub import {
	hook(type => "getsetup", id => "calendar", call => \&getsetup);
	hook(type => "needsbuild", id => "calendar", call => \&needsbuild);
	hook(type => "preprocess", id => "calendar", call => \&preprocess);
}

sub getsetup () {
	return
		plugin => {
			safe => 1,
			rebuild => undef,
		},
		archivebase => {
			type => "string",
			example => "archives",
			description => "base of the archives hierarchy",
			safe => 1,
			rebuild => 1,
		},
}

sub is_leap_year (@) {
	my %params=@_;
	return ($params{year} % 4 == 0 && (($params{year} % 100 != 0) || $params{year} % 400 == 0));
}

sub month_days {
	my %params=@_;
	my $days_in_month = (31,28,31,30,31,30,31,31,30,31,30,31)[$params{month}-1];
	if ($params{month} == 2 && is_leap_year(%params)) {
		$days_in_month++;
	}
	return $days_in_month;
}

sub format_month (@) {
	my %params=@_;

	my %linkcache;
	foreach my $p (pagespec_match_list($params{page}, $params{pages},
				# add presence dependencies to update
				# month calendar when pages are added/removed
				deptype => deptype("presence"))) {
		my $mtime = $IkiWiki::pagectime{$p};
		my @date  = localtime($mtime);
		my $mday  = $date[3];
		my $month = $date[4] + 1;
		my $year  = $date[5] + 1900;
		my $mtag  = sprintf("%02d", $month);

		# Only one posting per day is being linked to.
		$linkcache{"$year/$mtag/$mday"} = $p;
	}
		
	my $pmonth = $params{month} - 1;
	my $nmonth = $params{month} + 1;
	my $pyear  = $params{year};
	my $nyear  = $params{year};

	# Adjust for January and December
	if ($params{month} == 1) {
		$pmonth = 12;
		$pyear--;
	}
	if ($params{month} == 12) {
		$nmonth = 1;
		$nyear++;
	}

	my $calendar="\n";

	# When did this month start?
	my @monthstart = localtime(timelocal(0,0,0,1,$params{month}-1,$params{year}-1900));

	my $future_dom = 0;
	my $today      = 0;
	if ($params{year} == $now[5]+1900 && $params{month} == $now[4]+1) {
		$future_dom = $now[3]+1;
		$today      = $now[3];
	}

	# Find out month names for this, next, and previous months
	my $monthname=POSIX::strftime("%B", @monthstart);
	my $pmonthname=POSIX::strftime("%B", localtime(timelocal(0,0,0,1,$pmonth-1,$pyear-1900)));
	my $nmonthname=POSIX::strftime("%B", localtime(timelocal(0,0,0,1,$nmonth-1,$nyear-1900)));

	my $archivebase = 'archives';
	$archivebase = $config{archivebase} if defined $config{archivebase};
	$archivebase = $params{archivebase} if defined $params{archivebase};
  
	# Calculate URL's for monthly archives.
	my ($url, $purl, $nurl)=("$monthname",'','');
	if (exists $pagesources{"$archivebase/$params{year}/$params{month}"}) {
		$url = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$params{year}/".sprintf("%02d", $params{month}),
			linktext => " $monthname ");
	}
	add_depends($params{page}, "$archivebase/$params{year}/".sprintf("%02d", $params{month}),
		deptype("presence"));
	if (exists $pagesources{"$archivebase/$pyear/$pmonth"}) {
		$purl = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$pyear/" . sprintf("%02d", $pmonth),
			linktext => " $pmonthname ");
	}
	add_depends($params{page}, "$archivebase/$pyear/".sprintf("%02d", $pmonth),
		deptype("presence"));
	if (exists $pagesources{"$archivebase/$nyear/$nmonth"}) {
		$nurl = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$nyear/" . sprintf("%02d", $nmonth),
			linktext => " $nmonthname ");
	}
	add_depends($params{page}, "$archivebase/$nyear/".sprintf("%02d", $nmonth),
		deptype("presence"));

	# Start producing the month calendar
	$calendar=<<EOF;
<table class="month-calendar">
	<caption class="month-calendar-head">
	$purl
	$url
	$nurl
	</caption>
	<tr>
EOF

	# Suppose we want to start the week with day $week_start_day
	# If $monthstart[6] == 1
	my $week_start_day = $params{week_start_day};

	my $start_day = 1 + (7 - $monthstart[6] + $week_start_day) % 7;
	my %downame;
	my %dowabbr;
	for my $dow ($week_start_day..$week_start_day+6) {
		my @day=localtime(timelocal(0,0,0,$start_day++,$params{month}-1,$params{year}-1900));
		my $downame = POSIX::strftime("%A", @day);
		my $dowabbr = POSIX::strftime("%a", @day);
		$downame{$dow % 7}=$downame;
		$dowabbr{$dow % 7}=$dowabbr;
		$calendar.= qq{\t\t<th class="month-calendar-day-head $downame">$dowabbr</th>\n};
	}

	$calendar.=<<EOF;
	</tr>
EOF

	my $wday;
	# we start with a week_start_day, and skip until we get to the first
	for ($wday=$week_start_day; $wday != $monthstart[6]; $wday++, $wday %= 7) {
		$calendar.=qq{\t<tr>\n} if $wday == $week_start_day;
		$calendar.=qq{\t\t<td class="month-calendar-day-noday $downame{$wday}">&nbsp;</td>\n};
	}

	# At this point, either the first is a week_start_day, in which case
	# nothing has been printed, or else we are in the middle of a row.
	for (my $day = 1; $day <= month_days(year => $params{year}, month => $params{month});
	     $day++, $wday++, $wday %= 7) {
		# At tihs point, on a week_start_day, we close out a row,
		# and start a new one -- unless it is week_start_day on the
		# first, where we do not close a row -- since none was started.
		if ($wday == $week_start_day) {
			$calendar.=qq{\t</tr>\n} unless $day == 1;
			$calendar.=qq{\t<tr>\n};
		}
		
		my $tag;
		my $mtag = sprintf("%02d", $params{month});
		if (defined $linkcache{"$params{year}/$mtag/$day"}) {
			if ($day == $today) {
				$tag='month-calendar-day-this-day';
			}
			else {
				$tag='month-calendar-day-link';
			}
			$calendar.=qq{\t\t<td class="$tag $downame{$wday}">};
			$calendar.=htmllink($params{page}, $params{destpage}, 
			                    $linkcache{"$params{year}/$mtag/$day"},
			                    "linktext" => "$day");
			$calendar.=qq{</td>\n};
		}
		else {
			if ($day == $today) {
				$tag='month-calendar-day-this-day';
			}
			elsif ($day == $future_dom) {
				$tag='month-calendar-day-future';
			}
			else {
				$tag='month-calendar-day-nolink';
			}
			$calendar.=qq{\t\t<td class="$tag $downame{$wday}">$day</td>\n};
		}
	}

	# finish off the week
	for (; $wday != $week_start_day; $wday++, $wday %= 7) {
		$calendar.=qq{\t\t<td class="month-calendar-day-noday $downame{$wday}">&nbsp;</td>\n};
	}
	$calendar.=<<EOF;
	</tr>
</table>
EOF

	return $calendar;
}

sub format_year (@) {
	my %params=@_;
		
	my $calendar="\n";
	
	my $pyear = $params{year}  - 1;
	my $nyear = $params{year}  + 1;

	my $future_month = 0;
	$future_month = $now[4]+1 if ($params{year} == $now[5]+1900);

	my $archivebase = 'archives';
	$archivebase = $config{archivebase} if defined $config{archivebase};
	$archivebase = $params{archivebase} if defined $params{archivebase};

	# calculate URL's for previous and next years
	my ($url, $purl, $nurl)=("$params{year}",'','');
	if (exists $pagesources{"$archivebase/$params{year}"}) {
		$url = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$params{year}",
			linktext => "$params{year}");
	}
	add_depends($params{page}, "$archivebase/$params{year}", deptype("presence"));
	if (exists $pagesources{"$archivebase/$pyear"}) {
		$purl = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$pyear",
			linktext => "\&larr;");
	}
	add_depends($params{page}, "$archivebase/$pyear", deptype("presence"));
	if (exists $pagesources{"$archivebase/$nyear"}) {
		$nurl = htmllink($params{page}, $params{destpage}, 
			"$archivebase/$nyear",
			linktext => "\&rarr;");
	}
	add_depends($params{page}, "$archivebase/$nyear", deptype("presence"));

	# Start producing the year calendar
	$calendar=<<EOF;
<table class="year-calendar">
	<caption class="year-calendar-head">
	$purl
	$url
	$nurl
	</caption>
	<tr>
		<th class="year-calendar-subhead" colspan="$params{months_per_row}">Months</th>
	</tr>
EOF

	for (my $month = 1; $month <= 12; $month++) {
		my @day=localtime(timelocal(0,0,0,15,$month-1,$params{year}-1900));
		my $murl;
		my $monthname = POSIX::strftime("%B", @day);
		my $monthabbr = POSIX::strftime("%b", @day);
		$calendar.=qq{\t<tr>\n}  if ($month % $params{months_per_row} == 1);
		my $tag;
		my $mtag=sprintf("%02d", $month);
		if ($month == $params{month}) {
			if ($pagesources{"$archivebase/$params{year}/$mtag"}) {
				$tag = 'this_month_link';
			}
			else {
				$tag = 'this_month_nolink';
			}
		}
		elsif ($pagesources{"$archivebase/$params{year}/$mtag"}) {
			$tag = 'month_link';
		} 
		elsif ($future_month && $month >= $future_month) {
			$tag = 'month_future';
		} 
		else {
			$tag = 'month_nolink';
		}

		if ($pagesources{"$archivebase/$params{year}/$mtag"}) {
			$murl = htmllink($params{page}, $params{destpage}, 
				"$archivebase/$params{year}/$mtag",
				linktext => "$monthabbr");
			$calendar.=qq{\t<td class="$tag">};
			$calendar.=$murl;
			$calendar.=qq{\t</td>\n};
		}
		else {
			$calendar.=qq{\t<td class="$tag">$monthabbr</td>\n};
		}
		add_depends($params{page}, "$archivebase/$params{year}/$mtag",
			deptype("presence"));

		$calendar.=qq{\t</tr>\n} if ($month % $params{months_per_row} == 0);
	}

	$calendar.=<<EOF;
</table>
EOF

	return $calendar;
}

sub preprocess (@) {
	my %params=@_;

	my $thisyear=1900 + $now[5];
	my $thismonth=1 + $now[4];

	$params{pages} = "*"            unless defined $params{pages};
	$params{type}  = "month"        unless defined $params{type};
	$params{week_start_day} = 0     unless defined $params{week_start_day};
	$params{months_per_row} = 3     unless defined $params{months_per_row};
	$params{year}  = $thisyear	unless defined $params{year};
	$params{month} = $thismonth	unless defined $params{month};

	$params{month} = sprintf("%02d", $params{month});
			
	if ($params{type} eq 'month' && $params{year} == $thisyear
	    && $params{month} == $thismonth) {
		# calendar for current month, updates next midnight
		$pagestate{$params{destpage}}{calendar}{nextchange}=($time
			+ (60 - $now[0])		# seconds
			+ (59 - $now[1]) * 60		# minutes
			+ (23 - $now[2]) * 60 * 60	# hours
		);
	}
	elsif ($params{type} eq 'month' &&
	       (($params{year} == $thisyear && $params{month} > $thismonth) ||
	        $params{year} > $thisyear)) {
		# calendar for upcoming month, updates 1st of that month
		$pagestate{$params{destpage}}{calendar}{nextchange}=
			timelocal(0, 0, 0, 1, $params{month}-1, $params{year});
	}
	elsif ($params{type} eq 'year' && $params{year} == $thisyear) {
		# calendar for current year, updates 1st of next month
		$pagestate{$params{destpage}}{calendar}{nextchange}=
			timelocal(0, 0, 0, 1, $thismonth+1-1, $params{year});
	}
	elsif ($params{type} eq 'year' && $params{year} > $thisyear) {
		# calendar for upcoming year, updates 1st of that year
		$pagestate{$params{destpage}}{calendar}{nextchange}=
			timelocal(0, 0, 0, 1, 1-1, $params{year});
	}
	else {
		# calendar for past month or year, does not need
		# to update any more
		delete $pagestate{$params{destpage}}{calendar};
	}

	# Calculate month names for next month, and previous months
	my $calendar="";
	if ($params{type} eq 'month') {
		$calendar=format_month(%params);
	}
	elsif ($params{type} eq 'year') {
		$calendar=format_year(%params);
	}

	return "\n<div><div class=\"calendar\">$calendar</div></div>\n";
} #}}

sub needsbuild (@) {
	my $needsbuild=shift;
	foreach my $page (keys %pagestate) {
		if (exists $pagestate{$page}{calendar}{nextchange}) {
			if ($pagestate{$page}{calendar}{nextchange} <= $time) {
				# force a rebuild so the calendar shows
				# the current day
				push @$needsbuild, $pagesources{$page};
			}
			if (exists $pagesources{$page} && 
			    grep { $_ eq $pagesources{$page} } @$needsbuild) {
				# remove state, will be re-added if
				# the calendar is still there during the
				# rebuild
				delete $pagestate{$page}{calendar};
			}
		}
	}
}

1
