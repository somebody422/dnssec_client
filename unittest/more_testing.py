"""

Some more unittest usage. In particular will break down
 making suites and running them

"""


import unittest


class TestStringMethods(unittest.TestCase):
	# Do one-time setup for this TestCase
	def setUp(self):
		pass

	# Do one-time tear-down for this TestCase
	def tearDown(self):
		pass

	def test_upper(self):
		self.assertEqual('foo'.upper(), 'FOO')

	def test_isupper(self):
		self.assertTrue('FOO'.isupper())
		self.assertFalse('Foo'.isupper())

	def test_split(self):
		s = 'hello world'
		self.assertEqual(s.split(), ['hello', 'world'])
		# check that s.split fails when the separator is not a string
		with self.assertRaises(TypeError):
			s.split(2)

class TestArithmetic(unittest.TestCase):
	def test_multiplication(self):
		self.assertEqual(4, 2*2)

	def test_addition(self):
		self.assertEqual(452, 50 + 402)


# A silly function to show how FunctionTestCase works
def testSomethingThenFail():
	assert(1 == 1)
	assert(1 == 2)
def aSetupFunction():
	pass
def aTeardownFunction():
	pass


if __name__ == '__main__':

	# Create a suite which aggregates the tests. Here are a few ways
	#  to do this:

	# Use TestLoader: this will only pull in test from one TestCase
	string_methods_suite = unittest.TestLoader().loadTestsFromTestCase(TestStringMethods)

	# Use TestLoader to make a suite for each then make an aggregate suite
	test_classes = [TestStringMethods, TestArithmetic]
	test_suites = []
	test_loader = unittest.TestLoader()
	for test_class in test_classes:
		test_suites.append(test_loader.loadTestsFromTestCase(test_class))
	aggregate_suites = unittest.TestSuite(test_suites)

	# Add test cases individually
	individual_test_suite = unittest.TestSuite()
	individual_test_suite.addTest(TestStringMethods('test_upper'))
	individual_test_suite.addTest(TestStringMethods('test_isupper'))
	# ... ect

	# Note that we can also turn an arbitrary funciton into a test case:
	funciton_test_case = unittest.FunctionTestCase(
		testSomethingThenFail,
		setUp=aSetupFunction,
		tearDown=aTeardownFunction
	)

	# If the next line is uncommented, the suite should fail when run
	#aggregate_suites.addTest(funciton_test_case)

	# Now it is time to run the test suite
	runner = unittest.TextTestRunner()
	# Use the aggregate one for this example
	results = runner.run(aggregate_suites)
