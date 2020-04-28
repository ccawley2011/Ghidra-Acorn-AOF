/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package AcornAOF;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;

public class AcornChunkParser {
	private final static long MAGIC = 0xC3CBC6C5L;

	private long magic;
	private long maxchunks;
	private long numchunks;

	public static class Chunk {
		String id;
		long offset;
		long size;
	}
	private ArrayList<Chunk> chunks = new ArrayList<>();

	private ByteProvider provider;

	public AcornChunkParser(ByteProvider provider) throws IOException {
		this.provider = provider;

		BinaryReader reader = new BinaryReader(provider, true);
		magic = reader.readNextUnsignedInt();
		if (magic != MAGIC)
			return;

		maxchunks = reader.readNextUnsignedInt();
		numchunks = reader.readNextUnsignedInt();

		for (int i = 0; i < maxchunks; i++) {
			Chunk chunk = new Chunk();
			chunk.id = reader.readNextAsciiString(8);
			chunk.offset = reader.readNextUnsignedInt();
			chunk.size = reader.readNextUnsignedInt();
			chunks.add(chunk);
		}
	}

	public boolean isValid() {
		return (magic == MAGIC);
	}

	public boolean contains(String id) {
		for (Chunk chunk : chunks) {
			if (id.equals(chunk.id))
				return true;
		}
		return false;
	}

	public Chunk getChunk(long index) {
		if (index >= maxchunks)
			return null;

		return chunks.get((int)index);
	}

	public ByteProvider getByteProviderForChunk(long index) {
		Chunk chunk = getChunk(index);
		if (chunk == null)
			return null;

		return new ByteProviderWrapper(provider, chunk.offset, chunk.size);
	}

	public ByteProvider getByteProviderForChunk(String id) {
		for (Chunk chunk : chunks) {
			if (id.equals(chunk.id))
				return new ByteProviderWrapper(provider, chunk.offset, chunk.size);
		}
		return null;
	}
}
