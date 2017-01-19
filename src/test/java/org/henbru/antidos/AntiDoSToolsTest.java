package org.henbru.antidos;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Testsuite for all Anti-DoS classes
 */
public class AntiDoSToolsTest extends TestCase {

	public AntiDoSToolsTest(String testName) {
		super(testName);
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		TestSuite allTests = new TestSuite();

		allTests.addTestSuite(AntiDoSCounterTest.class);
		allTests.addTestSuite(AntiDoSSlotTest.class);
		allTests.addTestSuite(AntiDoSMonitorTest.class);
		allTests.addTestSuite(AntiDoSValveTest.class);

		return allTests;
	}
}
