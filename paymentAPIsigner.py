
# Burp extension to sign Payment Gateway API requests by calculating a variation of a HMAC-SHA512 and adding it to the request.
# This was written for a penetration test of a specific client's bespoke API but can serve as a template for similar Burp extensions to be modified as needed.

# https://github.com/TartarusLabs/Burp-Request-Signer
# james.fell@tartaruslabs.com


from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.io import PrintWriter
import hashlib

class BurpExtender(IBurpExtender, IHttpListener, IParameter):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName ("Payment Gateway API keyed SHA512 Signature Generator")
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		callbacks.registerHttpListener(self)
		print "Payment Gateway API Extension registered successfully."
		return

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

		# Only proceed if message is targeting the correct FQDN, is a request not a response, and is not from the proxy tool
		if messageInfo.getHttpService().toString() != "https://api.staging.tartaruslabs.com":
			return
		if not messageIsRequest:
			return
		if toolFlag == self._callbacks.TOOL_PROXY:
			return

		# Set your key here. This is issued by the API owner and linked to your individual user account.
		myKey = "4bc2da3b571a7c441d"

		self._stdout.println(("HTTP request to ") + messageInfo.getHttpService().toString() + " [" + self._callbacks.getToolName(toolFlag) + "]")

		rawRequest = messageInfo.getRequest()
		request = self._helpers.analyzeRequest(rawRequest)
		params = request.getParameters()
		requestBody = self._helpers.bytesToString(rawRequest[request.getBodyOffset():])

		# Build up a string of the request parameters in the format needed prior to applying the SHA512
		parameterStringList = []
		for x in params:
			if (x.getValue() != "") and (x.getValue() != "NULL"):
				parameterStringList.append(x.getName() + "=" + x.getValue() + myKey)
		parameterStringListSorted = sorted(parameterStringList, key=lambda s: s.lower())
		parameterString = ''.join(parameterStringListSorted)

		print parameterString

		# Generate the signature parameter to add on to the end of the request
		mySignature = "&signature=" + hashlib.sha512(parameterString.encode()).hexdigest()

		# Update the request ready to be sent
		updatedBody = requestBody + mySignature
		updatedRequest = self._helpers.buildHttpMessage(request.getHeaders(), updatedBody)
		messageInfo.setRequest(updatedRequest)
