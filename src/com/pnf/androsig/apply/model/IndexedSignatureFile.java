/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnfsoftware.jeb.util.encoding.Conversion;
import com.pnfsoftware.jeb.util.io.EndianUtil;
import com.pnfsoftware.jeb.util.io.IO;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Index File are built to speed up the signature recognition. It resolve memory access with
 * {@link RandomAccessFile} instead of reading whole files.
 * 
 * @author Cedric Lucas
 *
 */
public class IndexedSignatureFile implements ISignatureFile {

    private static final int CURRENT_INDEX_VERSION = 2;
    private static final boolean FORCE_GENERATION = false;
    private static final ILogger logger = GlobalLog.getLogger(IndexedSignatureFile.class);

    private Map<String, List<Integer>> tightSignaturesIdx = new HashMap<>();
    private Map<String, List<Integer>> looseSignaturesIdx = new HashMap<>();
    private Map<String, List<Integer>> signaturesByClassnameIdx = new HashMap<>();
    private Map<String, List<Integer>> signaturesByMethodsIdx = new HashMap<>();

    private Map<String, List<MethodSignature>> tightSignatures = new HashMap<>();
    private Map<String, List<MethodSignature>> looseSignatures = new HashMap<>();
    private Map<String, List<MethodSignature>> signaturesByClassname = new HashMap<>();
    private Map<String, List<MethodSignature>> signaturesByMethod = new HashMap<>();
    private Map<String, List<MethodSignature>> metaByClassname = new HashMap<>();
    private LibraryInfo libraryInfo;
    private int allSignatureCount = 0;

    private File sigFile;
    private RandomAccessFile f = null;

    public boolean loadSignatures(File sigFile) {
        if(this.sigFile != null) {
            throw new RuntimeException("Can only load one signature file");
        }
        this.sigFile = sigFile;
        File indexFile = getIndexFile(sigFile);
        if(!indexFile.exists()) {
            return false;
        }
        Charset utf8 = Charset.forName("UTF-8");
        libraryInfo = getLibraryInfo(sigFile, utf8);

        try {
            byte[] data = Files.readAllBytes(indexFile.toPath());
            int startIndex = 0;
            int index = validateHeader(sigFile, indexFile, data);
            if(FORCE_GENERATION || index < 0) {
                if(!buildIndexFile(sigFile, indexFile)) {
                    return false;
                }
                data = Files.readAllBytes(indexFile.toPath());
                index = validateHeader(sigFile, indexFile, data);
                if(index < 0) {
                    return false;
                }
            }
            Map<String, List<Integer>> currentList = tightSignaturesIdx;
            while(index < data.length) {
                if(IndexLine.isSeparator(data[index])) {
                    IndexLine line = IndexLine.parseLine(data, startIndex, index, utf8, false);
                    currentList.put(line.mhash, line.indexes);
                    index = line.index;
                    startIndex = index;
                    if(currentList == signaturesByClassnameIdx) {
                        allSignatureCount += line.nb;
                    }
                    if(index >= data.length) {
                        break;
                    }
                    if(IndexLine.isSectionSeparator(data[index])) {
                        index++;
                        startIndex = index;
                        if(currentList == tightSignaturesIdx) {
                            currentList = looseSignaturesIdx;
                        }
                        else if(currentList == looseSignaturesIdx) {
                            currentList = signaturesByClassnameIdx;
                        }
                        else if(currentList == signaturesByClassnameIdx) {
                            currentList = signaturesByMethodsIdx;
                        }
                        else {
                            break;
                        }
                    }
                    continue;
                }
                index++;
            }
        }
        catch(IOException e) {
            logger.catchingSilent(e);
            return false;
        }
        return true;
    }

    private LibraryInfo getLibraryInfo(File sigFile, Charset encoding) {
        int version = 0;
        String libname = "Unknown library code";
        String author = "Unknown author";
        LibraryInfo libraryInfo = new LibraryInfo();
        libraryInfo.setLibName(libname);
        libraryInfo.setAuthor(author);
        try(FileInputStream input = new FileInputStream(sigFile)) {
            try(BufferedReader br = new BufferedReader(new InputStreamReader(input, encoding))) {
                String line;
                while((line = br.readLine()) != null) {
                    if(line.startsWith(";")) {
                        line = line.substring(1);

                        String value = checkMarker(line, "version");
                        if(value != null) {
                            version = Conversion.stringToInt(value);
                            libraryInfo.setVersion(version);
                        }

                        value = checkMarker(line, "libname");
                        if(value != null) {
                            libname = value;
                            libraryInfo.setLibName(libname);
                        }

                        value = checkMarker(line, "author");
                        if(value != null) {
                            author = value;
                            libraryInfo.setAuthor(author);
                        }
                        continue;
                    }
                    else if(!line.isEmpty()) {
                        // end of header
                        break;
                    }
                }
            }
        }
        catch(IOException e) {
            logger.catchingSilent(e);
        }

        return libraryInfo;
    }

    private String checkMarker(String line, String marker) {
        if(line.startsWith(marker + "=")) {
            return line.substring(marker.length() + 1).trim();
        }
        return null;
    }

    private static int readInt(byte[] data, int offset) {
        return EndianUtil.bigEndianBytesToInt(data, offset);
    }

    @Override
    public LibraryInfo getLibraryInfos() {
        return libraryInfo;
    }

    @Override
    public List<MethodSignature> getTightSignatures(String hashcode) {
        List<MethodSignature> res = tightSignatures.get(hashcode);
        if(res == null) {
            res = load(tightSignaturesIdx, hashcode, tightSignatures);
        }
        if(res.isEmpty()) {
            return null;
        }
        return res;
    }

    private List<MethodSignature> load(Map<String, List<Integer>> mapIdx, String hashcode,
            Map<String, List<MethodSignature>> map) {
        List<MethodSignature> signatures = load(mapIdx, hashcode, map, null);
        mergeSignatures(signatures);
        return signatures;
    }

    private void mergeSignatures(List<MethodSignature> signatures) {
        mergeSignatures(signatures, null);
    }

    private void mergeSignatures(List<MethodSignature> signatures, List<MethodSignature> allMethods) {
        if(signatures == null) {
            // preventive: for meta essentially
            return;
        }
        boolean refreshClassname = allMethods == null;
        for(int i = 0; i < signatures.size(); i++) {
            // first remove duplicated lines
            MethodSignature ref = signatures.get(i);
            for(int j = i + 1; j < signatures.size(); j++) {
                MethodSignature current = signatures.get(j);
                if(MethodSignature.equalsClassMethodSig(ref, current)) {
                    // same signature
                    signatures.remove(j);
                    j--;
                }
            }

            // second, include same methods
            boolean shared = false;
            if(refreshClassname) {
                String key = ref.getCname() + "->" + ref.getMname();
                List<Integer> sameMethods = signaturesByMethodsIdx.get(key);
                if(sameMethods == null || sameMethods.size() == 2) {
                    continue; // only one
                }
                allMethods = signaturesByClassname.get(ref.getCname());
                if(allMethods == null) {
                    allMethods = load(signaturesByMethodsIdx, key, signaturesByMethod, null);
                }
                else {
                    shared = true;
                }
            }
            if(allMethods.size() == 1) {
                continue;
            }
            for(MethodSignature m: allMethods) {
                if(m == ref) {
                    continue;
                }
                if(MethodSignature.equalsMethodSig(ref, m)) {
                    if(shared) {
                        signatures.set(i, m);
                    }
                    else {
                        ref.addRevision(m.getOwnRevision());
                    }
                }
            }
        }
    }

    private List<MethodSignature> load(Map<String, List<Integer>> mapIdx, String hashcode,
            Map<String, List<MethodSignature>> map, Map<String, List<MethodSignature>> mapmeta) {
        List<MethodSignature> sigs = new ArrayList<>();
        List<MethodSignature> metaSigs = new ArrayList<>();
        map.put(hashcode, sigs);
        try {
            if(f == null) {
                f = new RandomAccessFile(sigFile, "r");
            }
            List<Integer> indexes = mapIdx.get(hashcode);
            if(indexes == null) {
                return sigs;
            }
            for(int i = 0; i < indexes.size(); i += 2) {
                int start = indexes.get(i);
                int end = indexes.get(i + 1);
                f.seek(start);
                byte[] lineBytes = new byte[end - start];
                f.read(lineBytes);
                String line = new String(lineBytes);
                MethodSignature m = MethodSignature.parse(line);
                if(m != null) {
                    sigs.add(m);
                }
                else if(mapmeta != null) {
                    m = MethodSignature.parse(line, false);
                    if(m != null) {
                        metaSigs.add(m);
                        mapmeta.put(hashcode, metaSigs);
                    }
                }
            }
            return sigs;
        }
        catch(IOException e) {
            logger.error("Can not read %s", sigFile);
        }
        return sigs;
    }

    @Override
    public List<MethodSignature> getLooseSignatures(String hashcode) {
        List<MethodSignature> res = looseSignatures.get(hashcode);
        if(res == null) {
            res = load(looseSignaturesIdx, hashcode, looseSignatures);
        }
        if(res.isEmpty()) {
            return null;
        }
        return res;
    }

    @Override
    public boolean hasSignaturesForClassname(String className) {
        return signaturesByClassnameIdx.get(className) != null;
    }

    @Override
    public List<MethodSignature> getSignaturesForClassname(String className, boolean exactName) {
        List<MethodSignature> compatibleSignatures = new ArrayList<>();
        if(exactName) {
            List<MethodSignature> res = signaturesByClassname.get(className);
            if(res == null) {
                res = load(signaturesByClassnameIdx, className, signaturesByClassname, metaByClassname);
                List<MethodSignature> ref = new ArrayList<>(res);
                mergeSignatures(res, ref);
                mergeSignatures(metaByClassname.get(className), ref);
            }
            return res;
        }
        for(Entry<String, List<Integer>> entry: signaturesByClassnameIdx.entrySet()) {
            if(entry.getKey().startsWith(className)) {
                List<MethodSignature> ms = getSignaturesForClassname(entry.getKey(), true);
                if(ms != null) {
                    compatibleSignatures.addAll(ms);
                }
            }
        }
        return compatibleSignatures;
    }

    @Override
    public List<MethodSignature> getParent(String className) {
        // load
        getSignaturesForClassname(className, true);
        return metaByClassname.get(className);
    }

    @Override
    public int getAllSignatureCount() {
        return allSignatureCount;
    }

    public static boolean buildIndexFile(File sigFile, File indexFile) {
        long fileSize = sigFile.length();
        if(fileSize > Integer.MAX_VALUE) {
            throw new RuntimeException("Signature file is too big. Is it really a signature file? If so, split it.");
        }
        Charset utf8 = Charset.forName("UTF-8");
        Map<String, List<Integer>> tightHashcodes = new HashMap<>();
        Map<String, List<Integer>> looseHashcodes = new HashMap<>();
        Map<String, List<Integer>> classes = new HashMap<>();
        Map<String, List<Integer>> methods = new HashMap<>();
        try {
            byte[] data = Files.readAllBytes(sigFile.toPath());
            int startIndex = 0;
            int endIndex = 0;
            while((endIndex = getNextLine(data, startIndex)) != -1) {
                if(data[startIndex] == ';') {
                    startIndex = endIndex + 1;
                    continue;
                }

                String[] subLines = MethodSignature.parseNative(data, startIndex, endIndex);
                if(subLines == null) {
                    logger.warn("Invalid parameter signature line at index " + startIndex + " in file " + sigFile);
                    startIndex = endIndex + 1;
                    continue;
                }

                String mhash_tight = MethodSignature.getTightSignature(subLines);
                if(mhash_tight != null && !mhash_tight.isEmpty() && !mhash_tight.equals("null")) {
                    List<Integer> files = tightHashcodes.get(mhash_tight);
                    if(files == null) {
                        files = new ArrayList<>();
                        tightHashcodes.put(mhash_tight, files);
                    }
                    files.add(startIndex);
                    files.add(endIndex);
                }
                String mhash_loose = MethodSignature.getLooseSignature(subLines);
                if(mhash_loose != null && !mhash_loose.isEmpty() && !mhash_loose.equals("null")) {
                    List<Integer> files = looseHashcodes.get(mhash_loose);
                    if(files == null) {
                        files = new ArrayList<>();
                        looseHashcodes.put(mhash_loose, files);
                    }
                    files.add(startIndex);
                    files.add(endIndex);
                }
                String className = MethodSignature.getClassname(subLines);
                if(className != null && !className.isEmpty()) {
                    List<Integer> files = classes.get(className);
                    if(files == null) {
                        files = new ArrayList<>();
                        classes.put(className, files);
                    }
                    files.add(startIndex);
                    files.add(endIndex);
                    String methodName = MethodSignature.getMethodName(subLines);
                    if(methodName != null && !methodName.isEmpty()) {
                        String key = className + "->" + methodName;
                        List<Integer> filesM = methods.get(key);
                        if(filesM == null) {
                            filesM = new ArrayList<>();
                            methods.put(key, filesM);
                        }
                        filesM.add(startIndex);
                        filesM.add(endIndex);
                    }
                }
                startIndex = endIndex + 1;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffInt = new byte[4];

            // header
            writeInt(buffInt, CURRENT_INDEX_VERSION, bos); // version
            writeInt(buffInt, (int)fileSize, bos); // filesize
            bos.write('\n');
            bos.write('\n');


            // tight section
            writeSection(bos, utf8, buffInt, tightHashcodes);

            // loose section
            bos.write('\n');
            writeSection(bos, utf8, buffInt, looseHashcodes);

            // classes section
            bos.write('\n');
            writeSection(bos, utf8, buffInt, classes);

            bos.write('\n');
            writeMethodSection(bos, utf8, buffInt, methods);

            IO.writeFile(indexFile, bos.toByteArray());
        }
        catch(IOException e) {
            logger.catching(e);
            return false;
        }
        return true;
    }

    private static void writeSection(ByteArrayOutputStream bos, Charset utf8, byte[] buffInt,
            Map<String, List<Integer>> classes) throws IOException {
        for(Entry<String, List<Integer>> entry: classes.entrySet()) {
            bos.write(entry.getKey().getBytes(utf8));
            bos.write('=');
            writeInt(buffInt, entry.getValue().size(), bos);
            for(Integer address: entry.getValue()) {
                writeInt(buffInt, address, bos);
            }
            bos.write('\n');
        }
    }

    private static void writeMethodSection(ByteArrayOutputStream bos, Charset utf8, byte[] buffInt,
            Map<String, List<Integer>> classes) throws IOException {
        for(Entry<String, List<Integer>> entry: classes.entrySet()) {
            if(entry.getValue().size() == 2) {
                continue; // only save duplicated entries
            }
            bos.write(entry.getKey().getBytes(utf8));
            bos.write('=');
            writeInt(buffInt, entry.getValue().size(), bos);
            for(Integer address: entry.getValue()) {
                writeInt(buffInt, address, bos);
            }
            bos.write('\n');
        }
    }

    private static void writeInt(byte[] buffInt, int val, ByteArrayOutputStream bos) throws IOException {
        EndianUtil.intToBEBytes(val, buffInt);
        bos.write(buffInt);
    }

    private static int getNextLine(byte[] data, int startIndex) {
        if(startIndex == data.length) {
            return -1;
        }
        int index = startIndex;
        while(data[index] != '\n') {
            index++;
            if(index == data.length) {
                return -1;
            }
        }
        return index;
    }

    public static File getIndexFile(File sigFile) {
        if(!sigFile.getName().endsWith(".sig")) {
            return null;
        }
        return new File(sigFile.getParentFile(),
                sigFile.getName().substring(0, sigFile.getName().length() - 4) + ".idx");
    }

    public static boolean populate(File sigFile, Map<String, Set<String>> allTightHashcodes,
            Map<String, Set<String>> allLooseHashcodes, Map<String, Set<String>> allClasses) {
        File indexFile = getIndexFile(sigFile);
        if(indexFile == null) {
            logger.error("Can not determine index file name. Is Signature extension is correct for %s?", sigFile);
            return false;
        }
        if(!indexFile.exists() && !buildIndexFile(sigFile, indexFile)) {
            return false;
        }

        // Read index file
        Charset utf8 = Charset.forName("UTF-8");
        try {
            byte[] data = Files.readAllBytes(indexFile.toPath());
            int startIndex = 0;
            int index = validateHeader(sigFile, indexFile, data);
            if(index < 0) {
                if(!buildIndexFile(sigFile, indexFile)) {
                    return false;
                }
                data = Files.readAllBytes(indexFile.toPath());
                index = validateHeader(sigFile, indexFile, data);
                if(index < 0) {
                    return false;
                }
            }
            Map<String, Set<String>> currentList = allTightHashcodes;
            while(index < data.length) {
                if(IndexLine.isSeparator(data[index])) {
                    IndexLine line = IndexLine.parseLine(data, startIndex, index, utf8, true);
                    Set<String> files = currentList.get(line.mhash);
                    if(files == null) {
                        files = new LinkedHashSet<>();
                        currentList.put(line.mhash, files);
                    }
                    files.add(sigFile.getAbsolutePath());

                    index = line.index;
                    startIndex = index;
                    if(index >= data.length) {
                        break;
                    }
                    if(IndexLine.isSectionSeparator(data[index])) {
                        index++;
                        startIndex = index;
                        if(currentList == allTightHashcodes) {
                            currentList = allLooseHashcodes;
                        }
                        else if(currentList == allLooseHashcodes) {
                            currentList = allClasses;
                        }
                        else {
                            break;
                        }
                    }
                    continue;
                }
                index++;
            }
        }
        catch(IOException e) {
            logger.catching(e);
            return false;
        }
        return true;
    }

    private static int validateHeader(File sigFile, File indexFile, byte[] data) {
        int index = 0;
        if(data.length < 10) {
            return -1;
        }
        int version = readInt(data, index);
        index += 4;
        if(version != CURRENT_INDEX_VERSION) {
            return -1;
        }
        int expectedSize = readInt(data, index);
        index += 4;
        if(expectedSize != sigFile.length()) {
            return -1;
        }
        index += 2; // line end + section end
        return index;
    }

    @Override
    public void close() throws IOException {
        if(f != null) {
            f.close();
        }

    }

    private static class IndexLine {
        String mhash;
        int index = 0;
        int nb = 0;
        List<Integer> indexes;

        public IndexLine(int endIndex) {
            index = endIndex;
        }
        static IndexLine parseLine(byte[] data, int startIndex, int endIndex, Charset utf8, boolean skip) {
            IndexLine line = new IndexLine(endIndex);
            line.mhash = new String(data, startIndex, line.index - startIndex, utf8);
            line.index++;
            line.nb = readInt(data, line.index);
            line.index += 4;

            if(skip) {
                line.index += line.nb * 4; // 4*address
            }
            else {
                line.indexes = new ArrayList<>();
                for(int i = 0; i < line.nb; i++) {
                    line.indexes.add(readInt(data, line.index));
                    line.index += 4;
                }
            }

            line.index++; // \n
            return line;
        }

        static boolean isSeparator(byte b) {
            return b == '=';
        }

        static boolean isSectionSeparator(byte b) {
            return b == '\n';
        }
    }

}
