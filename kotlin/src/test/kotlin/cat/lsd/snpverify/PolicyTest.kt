package cat.lsd.snpverify

// Cross-port policy vector: JSON policies with their resolved form, or the POLICY_INVALID message they produce (vectors/policy.json).
import com.google.gson.Gson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolicyTest {
    @Test fun matchesCrossPortPolicyVector() {
        val cases = Fixtures.json(Fixtures.vectors.resolve("policy.json"))
        assertTrue(cases.size() > 0)
        for ((name, c) in cases.entrySet()) {
            val policyEl = c.asJsonObject["policy"]
            val text = if (policyEl.isJsonPrimitive && policyEl.asJsonPrimitive.isString) policyEl.asString else policyEl.toString()
            val r = appraisalPolicyFromJson(text)
            val error = c.asJsonObject["error"]
            if (error != null) {
                val err = r as? Result.Err ?: error("$name: expected POLICY_INVALID")
                assertEquals(ErrorCode.POLICY_INVALID to error.asString, err.error.code to err.error.message, name)
                continue
            }
            val policy = (r as? Result.Ok ?: error("$name: ${(r as Result.Err).error}")).value
            val resolved = (resolveAppraisalPolicy(policy) as Result.Ok).value
            assertEquals(c.asJsonObject["resolved"], Gson().toJsonTree(appraisalPolicyToJson(resolved)), name)
        }
    }
}
