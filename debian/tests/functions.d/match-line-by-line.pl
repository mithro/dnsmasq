#!/usr/bin/perl

($#ARGV == 1) or die "Expecting two filenames\n";

my $file_to_match = $ARGV[0];
my $pattern_file = $ARGV[1];
my ($fh, $ph, $line_num, $line_to_match, $pattern_line);

open($fh, '<', $file_to_match) or die "Failed to open $file_to_match: $!\n";
open($ph, '<', $pattern_file) or die "Failed to open $pattern_file: $!\n";

$line_num = 1;
while (!eof($fh) && !eof($ph)) {
	$line_to_match = readline($fh);
	$pattern_line = readline($ph);
	($line_to_match =~ /^$pattern_line$/) or
		die "!!! MISMATCH !!!\n" .
			"   Line $line_num: $line_to_match" .
			"Pattern $line_num: $pattern_line";
	$line_num++;
}
!eof($fh) && eof($ph) and
	die "!!! MISMATCH !!!\n" .
		"$file_to_match has more lines than $pattern_file\n";
eof($fh) && !eof($ph) and
	die "!!! MISMATCH !!!\n" .
		"$file_to_match has less lines than $pattern_file\n";

exit 0;
