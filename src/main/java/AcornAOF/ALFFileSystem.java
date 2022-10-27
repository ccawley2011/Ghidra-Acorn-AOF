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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * ALF file system implementation.
 */
@FileSystemInfo(type = "alf", description = "ARM Object Library Format", factory = ALFFileSystem.ALFFileSystemFactory.class)
public class ALFFileSystem implements GFileSystem {

	private static class ALFMetadata {
		private long chunkindex;
		private long entrylength;
		private long datalength;
		private String name;

		private AcornChunkParser.Chunk chunk;
	}

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<ALFMetadata> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;
	private AcornChunkParser parser;

	/**
	 * File system constructor.
	 *
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public ALFFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 *
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Opening " + ALFFileSystem.class.getSimpleName() + "...");

		parser = new AcornChunkParser(provider);
		ByteProvider diry = parser.getByteProviderForChunk("LIB_DIRY");
		BinaryReader reader = new BinaryReader(diry, true);

		while (reader.getPointerIndex() < reader.length()) {
			monitor.checkCanceled();

			long start = reader.getPointerIndex();

			ALFMetadata metadata = new ALFMetadata();
			metadata.chunkindex = reader.readNextUnsignedInt();
			metadata.entrylength = reader.readNextUnsignedInt();
			metadata.datalength = reader.readNextUnsignedInt();
			metadata.name = reader.readNextAsciiString();

			reader.setPointerIndex(start + metadata.entrylength);

			metadata.chunk = parser.getChunk(metadata.chunkindex);
			if (metadata.chunk != null)
				fsih.storeFile(metadata.name, fsih.getFileCount(), false, metadata.chunk.size, metadata);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		ALFMetadata metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderWrapper(provider, metadata.chunk.offset, metadata.chunk.size,
					file.getFSRL())
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		ALFMetadata metadata = fsih.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			result.add(NAME_ATTR, metadata.name);
			result.add(SIZE_ATTR, metadata.chunk.size);
			result.add("Chunk index", metadata.chunkindex);
		}
		return result;
	}

	public static class ALFFileSystemFactory implements
			GFileSystemFactoryByteProvider<ALFFileSystem>, GFileSystemProbeByteProvider {

		@Override
		public ALFFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			ALFFileSystem fs = new ALFFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			AcornChunkParser parser = new AcornChunkParser(byteProvider);
			return parser.isValid() && parser.contains("LIB_DIRY");
		}
	}
}
