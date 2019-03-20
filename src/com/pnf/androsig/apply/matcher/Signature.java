/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.matcher;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.model.SignatureFile;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * The class contains all information about the signatures.
 * 
 * @author Ruoxiao Wang
 *
 */
class Signature implements ISignatureMetrics {
    private final ILogger logger = GlobalLog.getLogger(Signature.class);

    private final SignatureFile sigFile = new SignatureFile();

    // Record
    private int allUsedSignatureFileCount = 0;

    /**
     * Get the number of signatures.
     * 
     * @return the number of signatures
     */
    @Override
    public int getAllSignatureCount() {
        return sigFile.getAllSignatureCount();
    }

    /**
     * Get the number of used signature files.
     * 
     * @return the number of used signature files
     */
    @Override
    public int getAllUsedSignatureFileCount() {
        return allUsedSignatureFileCount;
    }

    /**
     * Get all information related to tight method signatures.
     * 
     * @return a Map (Key: the tight method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<MethodSignature>> getAllTightSignatures() {
        return sigFile.getAllTightSignatures();
    }

    /**
     * Get all information related to loose method signatures.
     * 
     * @return a Map (Key: the loose method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<MethodSignature>> getAllLooseSignatures() {
        return sigFile.getAllLooseSignatures();
    }

    /**
     * Get all library information.
     * 
     * @return a Map (Key: the class signature path. Value: LibraryInfo Object)
     */
    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        return sigFile.getAllLibraryInfos();
    }

    /**
     * Load all signatures.
     * 
     * @param unit mandatory target unit
     */
    public void loadAllSignatures(IDexUnit unit, DatabaseReference ref) {
        // Store all used signature files
        logger.info("Used Sig Files storing start...");
        final long startTime = System.currentTimeMillis();
        Set<String> usedSigFiles = new HashSet<>();
        storeAllUsedSigFiles(unit, usedSigFiles, ref);
        final long endTime = System.currentTimeMillis();
        logger.info("Used Sig Files storing completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");

        // Load all signatures
        logger.info("Library signatures loading start...");
        final long startTime1 = System.currentTimeMillis();
        File f;
        for(String filePath: usedSigFiles) {
            f = new File(filePath);
            if(!sigFile.loadSignatures(f)) {
                logger.error("Cannot load signatures files: %s", f);
            }
        }
        final long endTime1 = System.currentTimeMillis();
        logger.info("Library signatures loading completed! (Execution Time: " + (endTime1 - startTime1) / 1000 + "s)");
        allUsedSignatureFileCount = usedSigFiles.size();
        usedSigFiles.clear();
        long a = 0;
        for(List<MethodSignature> e: getAllTightSignatures().values()) {
            a += e.size();
        }
        long b = 0;
        for(List<MethodSignature> e: getAllLooseSignatures().values()) {
            b += e.size();
        }
        int allSigCount = getAllTightSignatures().size() + getAllLooseSignatures().size();
        long c = allSigCount == 0 ? -1: (a + b) / allSigCount;
        logger.info("Average candidates: " + c);

        logger.info("allTightSignatures map size: " + getAllTightSignatures().size());
        logger.info("candidates: " + a);
        logger.info("allLooseSignatures map size: " + getAllLooseSignatures().size());
        logger.info("candidates: " + b);
    }

    private void storeAllUsedSigFiles(IDexUnit dex, Set<String> usedSigFiles, DatabaseReference ref) {
        List<? extends IDexClass> classes = dex.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                continue;
            }
            for(IDexMethod eMethod: methods) {
                if(!eMethod.isInternal()) {
                    continue;
                }

                IDexMethodData md = eMethod.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    continue;
                }
                else {
                    boolean tightFlag = true; // Use tight sig
                    boolean looseFlag = true; // Use loose sig
                    String mhash_tight = SignatureHandler.generateTightHashcode(ci);
                    if(mhash_tight == null) {
                        tightFlag = false;
                    }
                    if(tightFlag) {
                        List<String> files = ref.getFilesContainingTightHashcode(mhash_tight);
                        if(files != null && !files.isEmpty()) {
                            usedSigFiles.add(files.get(files.size() - 1));
                            looseFlag = false;
                        }
                    }
                    if(looseFlag) {
                        String mhash_loose = SignatureHandler.generateLooseHashcode(ci);
                        if(mhash_loose == null) {
                            continue;
                        }
                        List<String> files = ref.getFilesContainingLooseHashcode(mhash_loose);
                        if(files != null && !files.isEmpty()) {
                            usedSigFiles.add(files.get(files.size() - 1));
                            looseFlag = false;
                        }
                    }
                }
            }
        }
    }
}
