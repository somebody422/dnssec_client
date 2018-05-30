
nose is a library to make unittest easier to use, and more powerful.

By default, nose will search for funcitons and classes which match this regex:
(?:^|[\\b_\\.-])[Tt]est
Basically, the word 'test' or 'Test' as a word boundry or after a '-' or '_'. Will also load test cases from TestCase subclasses.









