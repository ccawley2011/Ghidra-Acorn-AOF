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

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

/**
 * A {@link Loader} for processing AIF files.
 */
public class AIFLoader extends AbstractLibrarySupportLoader {

	public final static String AIF_NAME = "ARM Image Format (AIF)";

	private AIFHeader header;

	@Override
	public String getName() {
		return AIF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Support big endian AIFs
		BinaryReader reader = new BinaryReader(provider, true);

		if (reader.readUnsignedInt(0x10) == 0xEF000011L) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4","default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		header = new AIFHeader(reader);
		long position = 0;

		createSegment(fpa, provider.getInputStream(position), "Header", header.getBase() + position, 0x80, true, false, true, log);
		createData(program, fpa, header.toDataType(), header.getBase() + 0x14, -1, log);
		position += 0x80;

		// TODO: Support non-executable AIFs
		if (header.getReadOnlySize() > position) {
			createSegment(fpa, provider.getInputStream(position), "ReadOnly", header.getBase() + position, header.getReadOnlySize() - position, true, false, true, log);
			position += header.getReadOnlySize() - position;
		}

		if (header.getReadWriteSize() > 0) {
			createSegment(fpa, provider.getInputStream(position), "ReadWrite", header.getBase() + position, header.getReadWriteSize(), true, true, true, log);
			position += header.getReadWriteSize();
		}

		if (header.getDebugSize() > 0) {
			// TODO: Create DebugArea segment?
			position += header.getDebugSize();
		}

		if (header.getZeroInitSize() > 0) {
			createSegment(fpa, provider.getInputStream(position), "ZeroInit", header.getBase() + position, header.getZeroInitSize(), true, true, false, log);
		}
	}

	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
			boolean read, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createData(Program program, FlatProgramAPI fpa, DataType newDataType, long address, int size,
			MessageLog log) {
		try {
			DataUtilities.createData(program, fpa.toAddr(address), newDataType, size, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}
}
