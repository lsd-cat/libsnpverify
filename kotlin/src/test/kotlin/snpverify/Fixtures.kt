package snpverify

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.util.zip.GZIPInputStream

object Fixtures {
    val vectors: File = File(System.getProperty("vectors.dir") ?: "../vectors")
    fun json(f: File): JsonObject = JsonParser.parseString(f.readText()).asJsonObject
    fun gunzip(b: ByteArray): ByteArray = GZIPInputStream(b.inputStream()).readBytes()
}
