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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

class AIFHeader implements StructConverter {
    private long readOnlySize = 0;
    private long readWriteSize = 0;
    private long debugSize = 0;
    private long zeroInitSize = 0;
    private long debugType = 0;
    private long base = 0;
    private long workSpace = 0;
    private long addressMode = 0;
    private long database = 0;
    private long reserved1 = 0;
    private long reserved2 = 0;

    AIFHeader(BinaryReader reader) throws IOException {

        if (reader.length() < 0x44) {
            return;
        }

        reader.setPointerIndex(0x14);

        readOnlySize = reader.readNextUnsignedInt();
        readWriteSize = reader.readNextUnsignedInt();
        debugSize = reader.readNextUnsignedInt();
        zeroInitSize = reader.readNextUnsignedInt();
        debugType = reader.readNextUnsignedInt();
        base = reader.readNextUnsignedInt();
        workSpace = reader.readNextUnsignedInt();
        addressMode = reader.readNextUnsignedInt();
        database = reader.readNextUnsignedInt();
        reserved1 = reader.readNextUnsignedInt();
        reserved2 = reader.readNextUnsignedInt();
    }

    @Override
    public DataType toDataType() {
        Structure s = new StructureDataType("AIFHeader", 0);

        s.add(DWORD, 0x04, "ReadOnlySize", null);
        s.add(DWORD, 0x04, "ReadWriteSize", null);
        s.add(DWORD, 0x04, "DebugSize", null);
        s.add(DWORD, 0x04, "ZeroInitSize", null);
        s.add(DWORD, 0x04, "DebugType", null);
        s.add(DWORD, 0x04, "Base", null);
        s.add(DWORD, 0x04, "WorkSpace", null);
        s.add(DWORD, 0x04, "AddressMode", null);
        s.add(DWORD, 0x04, "DataBase", null);
        s.add(DWORD, 0x04, "Reserved1", null);
        s.add(DWORD, 0x04, "Reserved2", null);

        return s;
    }

    public long getReadOnlySize() {
        return readOnlySize;
    }

    public long getReadWriteSize() {
        return readWriteSize;
    }

    public long getDebugSize() {
        return debugSize;
    }

    public long getZeroInitSize() {
        return zeroInitSize;
    }

    public long getDebugType() {
        return debugType;
    }

    public long getBase() {
        return base;
    }

    public long getWorkSpace() {
        return workSpace;
    }

    public long getAddressMode() {
        return addressMode;
    }

    public long getDataBase() {
        return database;
    }
}
