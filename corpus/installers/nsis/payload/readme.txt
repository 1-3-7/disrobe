Tide Table Viewer
=================

Tide Table Viewer reads harbour tide predictions from a plain CSV file and
draws the next seven days as a height-over-time chart. It keeps no network
connection and writes nothing outside its own settings file.

Installing
----------

Run the installer and pick a folder. The program files, this readme and the
change log land in that folder; the sample station table lands in a data
subfolder beside them. Removing the folder removes the program.

Station tables
--------------

A station table has one row per prediction: the station name, the date in
ISO 8601 form, the local time on a 24-hour clock, the predicted height in
metres above chart datum, and a flag that marks the row as a high or a low
water. Rows may appear in any order; the viewer sorts them before drawing.

Heights below chart datum are negative. The chart clips them at the lower
edge and prints the exact value beside the marker, so a spring low of -0.3 m
stays readable even when the axis starts at zero.

Keyboard
--------

  Left, Right    move one day
  Home           return to today
  Plus, Minus    widen or narrow the time axis
  S              switch station
  Q              quit

Limits
------

The viewer loads at most 20 000 rows per table and ignores rows whose height
does not parse as a decimal number. It reports how many rows it skipped in the
status line rather than stopping at the first bad row.
