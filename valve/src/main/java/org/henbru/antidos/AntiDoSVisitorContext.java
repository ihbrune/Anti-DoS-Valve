package org.henbru.antidos;

/**
 * Immutable context object stored in the request attribute {@link AntiDoSValve#VISITOR_CONTEXT_ATTRIBUTE_NAME}
 * to share validated visitor / session state between multiple upstream and downstream valves.
 *
 * @param valid             whether the visitor cookie was successfully validated
 * @param counter           the visit counter extracted from the validated visitor cookie
 * @param subnetMaskV4      the IPv4 subnet mask bits configured/used during token evaluation
 * @param subnetMaskV6      the IPv6 subnet mask bits configured/used during token evaluation
 * @param subnetBytes       the raw subnet bytes extracted from the client IP address
 * @param uaMismatch        whether a User-Agent mismatch was detected between the token and current request
 */
public record AntiDoSVisitorContext(
		boolean valid,
		int counter,
		int subnetMaskV4,
		int subnetMaskV6,
		byte[] subnetBytes,
		boolean uaMismatch) {

	public AntiDoSVisitorContext(boolean valid, int counter, int subnetMaskV4, int subnetMaskV6, byte[] subnetBytes) {
		this(valid, counter, subnetMaskV4, subnetMaskV6, subnetBytes, false);
	}
}

