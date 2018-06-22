
An ORM connecting python to some SQL backend.
Save yourself a couple of clicks:
https://en.wikipedia.org/wiki/Object-relational_mapping
Or just read this:  Basically an ORM converts between 2 type systems that are not naturally compatible. In this case we have Python and SQL. A SQL database cannot store arbitrary objects: it uses scalar values. The ORM will convert fancy python objects and shit down to scalar things that fit nicely into a SQL database. Then it will convert them back when it queries the database.
