


Pattern matching - SQL can be used with things like regexes, but it also has its own simple built-in matching syntax. _ matches exactly 1 character, and % matches any number (including 0) of characters. A pattern comes after LIKE or NOT LIKE operators.
Ex:
'SELECT * FROM table WHERE name LIKE s__%' - select rows where name starts with s and is at least 3 characters long
Same example with a regex instead (assuming your distribution supports regexes):
'SELECT * FROM table WHERE name REGEXP '^s..''

'SELECT column1, column2' FROM table, WHERE condition ORDER BY column
'SELECt c1,c2 FROM table WHERE EXISTS (subquery...)' - EXISTS will return FALSE iff subquery returns no rows

'SHOW DATABASES' - show all databases

'SHOW TABLES' - list the tables for the current database

'DESCRIBE table' - describe the columns of table

'CREATE TABLE name (field1 type, field2 type, field3 type, ...);'
'CREATE TABLE table1 LIKE table2' - creates a table with the same columns as table2

If giving values for only some of the columns, you have to specify which columns. Otherwise it is assumed that each row is filled.
'INSERT INTO table (c1, c2, c5, c6) VALUES (v1, v2, v5, v6)'
'INSERT INTO table VALUES (v1, v2, v3, v4, v5, v6)'
'INSERT INTO table SELECT col1, col2 FROM table2 WHERE condition'

'REPLACE INTO table VALUES (v1, v2, v3, v4, v5, v6)' - REPLACE INTO is exactly like INSERT INTO, except if a row with the primary key already exists it will be deleted and replaced

'UPDATE table SET col1 = val1, col2=val2 WHERE condition' - statement to change rows in a table

'DELETE FROM table WHERE condition' - delete rows from a table. BEWARE: leaving out the where part will just delete all rows

Alter table can be used to do a couple of things:
'ALTER TABLE table variable = value' - will update a table var such as ROW_FORMAT, TABLESPACE, MAX_ROWS, ect.
'ALTER TABLE table ADD column_name type'
'ALTER TABLE table DROP column_name'
'ALTER TABLE table MODIFY COLUMN column type' - change type of column
'ALTER TABLE TABLE RENAME COLUMN column TO new_name'

===================================
=-=--=- Tips / Gotchas: -=-=-=-=-=-
===================================
ALTER statements tend to change databases or tables. UPDATE will just change rows in the table

The standard is to use single quotes instead of double

AND has a higher precedence than OR! Use parentheses

To count records which match some condition, combine COUNT() and GROUP BY. Ex:
'SELECT c1, COUNT(*) FROM table WHERE condition GROUP BY c1'


===================================
=-=-=-=-=- EXAMPLES: -=-=-=-=-==-=-
===================================

'SELECT Version();' - 1r, 1c table with version
'SELECT Version(), Current_Date;' - 1r, 2c table with version and date
'SELECT COUNT(*) FROM table1 WHERE id>50' - row counting!

'INSERT INTO table1 VALUES(val1, val2, val2), (val4, val2, val1)' - this will create rows inline, and add them into a table

'SELECT name, species, date_born FROM pets WHERE species = 'cat' OR species = 'dog' ORDER BY date_bord DESC;

'SELECT 0 IS NULL, 0 IS NOT NULL, '' IS NULL, '' IS NOT NULL' - Just demonstrates the "is null" syntax, and shows that 0 and empty string are not null! they are values and deserve respect.

'SELECT MAX(price) FROM SHOPS' - highest value for price.

'SELECT dealer, price FROM shops WHERE price = (SELECT MAX(price) FROM shops)' - Return stuff from the row with the highest price. Note the use of a subquery!
