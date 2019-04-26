/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * @author Cedric Lucas
 *
 */
public class SignatureFileFactory {
    private final ILogger logger = GlobalLog.getLogger(SignatureFileFactory.class);

    private static final int LIMIT_LOAD = 200;

    /** sigLines, with filename as key */
    private Map<String, ISignatureFile> sigLinePerFilename = new HashMap<>();
    private List<String> loadOrder = new ArrayList<>();

    public static boolean populate(File sigFile, Map<String, Set<String>> allTightHashcodes,
            Map<String, Set<String>> allLooseHashcodes, Map<String, Set<String>> allClasses) {
        //return SignatureFile.populate(sigFile, allTightHashcodes, allLooseHashcodes, allClasses);
        return IndexedSignatureFile.populate(sigFile, allTightHashcodes, allLooseHashcodes, allClasses);
    }

    private static ISignatureFile getSignatureFile(File sigF) {
        File indexFile = IndexedSignatureFile.getIndexFile(sigF);
        if(indexFile.exists()) {
            IndexedSignatureFile newSigFile = new IndexedSignatureFile();
            if(newSigFile.loadSignatures(sigF)) {
                return newSigFile;
            }
        }
        SignatureFile newSigFile = new SignatureFile();
        if(newSigFile.loadSignatures(sigF)) {
            return newSigFile;
        }
        return null;
    }

    @SuppressWarnings("resource")
    public ISignatureFile getSignatureFile(String file) {
        ISignatureFile sigFile = sigLinePerFilename.get(file);
        if(sigFile == null) {
            if(loadOrder.size() >= LIMIT_LOAD) {
                // delete half
                int deleted = LIMIT_LOAD / 2;
                for(int i = 0; i < deleted; i++) {
                    sigLinePerFilename.remove(loadOrder.remove(0));
                }
            }
            File sigF = new File(file);
            sigFile = SignatureFileFactory.getSignatureFile(sigF);
            sigLinePerFilename.put(file, sigFile);
            // logger.info("Load %s", file);
        }
        if(sigFile instanceof SignatureFile) {
            loadOrder.remove(file);
            loadOrder.add(file);
        }
        return sigFile;
    }

    public Map<String, ISignatureFile> getLoadedSignatureFiles() {
        return sigLinePerFilename;
    }

    public void close() {
        for(ISignatureFile sig: sigLinePerFilename.values()) {
            try {
                sig.close();
            }
            catch(IOException e) {
                logger.catchingSilent(e);
            }
        }
    }
}
