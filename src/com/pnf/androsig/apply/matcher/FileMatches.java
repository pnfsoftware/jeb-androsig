/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Keep a library of files/versions used and try to get coherence with one version.
 * 
 * @author Cedric Lucas
 *
 */
public class FileMatches {
    private final ILogger logger = GlobalLog.getLogger(FileMatches.class);

    private ContextMatches contextMatches;

    private Map<Integer, DatabaseReferenceFile> matchedClassesFile = new HashMap<>();

    /** Used files -> list of versions match (with occurrences) */
    private Map<String, DatabaseReferenceFile> usedSigFiles = new HashMap<>();
    private Map<String, DatabaseReferenceFile> tempSigFiles = new HashMap<>();

    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new LinkedHashMap<>();

    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new LinkedHashMap<>();
    private Map<Integer, MethodSignature> matchedSigMethods = new HashMap<>();

    /** Extended candidate list, not stable enough (several candidates for same class) */
    private Map<Integer, Set<DatabaseReferenceFile>> candidateMatchedClassesFile = new HashMap<>();

    public FileMatches(ContextMatches contextMatches) {
        this.contextMatches = contextMatches;
    }

    public Set<String> getSignatureFileUsed() {
        // TODO better to have some kind of alt values
        //Set<String> set = new HashSet<>();
        //set.addAll(tempSigFiles.keySet());
        //set.addAll(usedSigFiles.keySet());
        //return set;
        return usedSigFiles.keySet();
    }

    //    public Set<Entry<String, DatabaseReferenceFile>> getSignatureFileEntrySet() {
    //        return usedSigFiles.entrySet();
    //    }

    public boolean isSignatureFileUsed(String f) {
        return usedSigFiles.containsKey(f);
    }

    //    public DatabaseReferenceFile getFromFilename(String file) {
    //        return usedSigFiles.get(file);
    //    }

    public DatabaseReferenceFile getFileFromClass(IDexUnit dex, IDexClass dexClass) {
        if(dexClass == null) {
            return null;
        }
        DatabaseReferenceFile refFile = getFileFromClassId(dexClass.getIndex());
        if(refFile == null) {
            String signature = dexClass.getSignature(true);
            if(DexUtilLocal.isInnerClass(signature)) {
                refFile = getFileFromClass(dex, DexUtilLocal.getParentClass(dex, signature));
                if(refFile != null) {
                    matchedClassesFile.put(dexClass.getIndex(), refFile);
                }
            }
        }
        return refFile;
    }

    public DatabaseReferenceFile getFileFromClassId(int index) {
        return matchedClassesFile.get(index);
    }

    public Set<DatabaseReferenceFile> getCandidateFilesFromClass(IDexUnit dex, IDexClass dexClass) {
        if(dexClass == null) {
            return null;
        }
        Set<DatabaseReferenceFile> refFiles = candidateMatchedClassesFile.get(dexClass.getIndex());
        if(refFiles == null) {
            String signature = dexClass.getSignature(true);
            if(DexUtilLocal.isInnerClass(signature)) {
                refFiles = getCandidateFilesFromClass(dex, DexUtilLocal.getParentClass(dex, signature));
                if(refFiles != null) {
                    candidateMatchedClassesFile.put(dexClass.getIndex(), refFiles);
                }
            }
        }
        return refFiles;
    }

    private void addMatchedClassFiles(IDexClass dexClass, String file) {
        addMatchedClassFiles(dexClass.getIndex(), file);
    }

    private void addMatchedClassFiles(int dexClassIndex, String file) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        matchedClassesFile.put(dexClassIndex, refFile);
    }

    private void addMatchedClassFiles(int dexClassIndex, DatabaseReferenceFile refFile) {
        usedSigFiles.put(refFile.file, refFile);
        matchedClassesFile.put(dexClassIndex, refFile);
    }

    public DatabaseReferenceFile removeClassFiles(IDexClass dexClass) {
        return matchedClassesFile.remove(dexClass.getIndex());
    }

    private void addCandidates(IDexClass eClass, List<String> files) {
        for(String file: files) {
            DatabaseReferenceFile refFile = usedSigFiles.get(file);
            if(refFile == null) {
                refFile = tempSigFiles.get(file);
                if(refFile == null) {
                    refFile = new DatabaseReferenceFile(file, null);
                    tempSigFiles.put(file, refFile);
                }
            }
            Integer key = eClass.getIndex();
            Set<DatabaseReferenceFile> val = candidateMatchedClassesFile.get(key);
            if(val == null) {
                val = new HashSet<>();
                candidateMatchedClassesFile.put(key, val);
            }
            val.add(refFile);
        }
    }

    public void removeCandidateFile(DatabaseReferenceFile r) {
        Map<Integer, DatabaseReferenceFile> stableElements = new HashMap<>();
        DatabaseReferenceFile refFile = usedSigFiles.remove(r.file);
       for (Entry<Integer, Set<DatabaseReferenceFile>> entry : candidateMatchedClassesFile.entrySet()) {
           if (entry.getValue().remove(refFile)) {
               if (entry.getValue().size() == 1) {
                   // move from candidate
                   stableElements.put(entry.getKey(), entry.getValue().iterator().next());
               }
           }
       }
       for (Entry<Integer, DatabaseReferenceFile> entry : stableElements.entrySet()) {
            candidateMatchedClassesFile.remove(entry.getKey());
            addMatchedClassFiles(entry.getKey(), entry.getValue());
       }
    }

    /**
     * Save and merge versions used for one file.
     * 
     * @param file
     * @param values
     * @return
     */
    private boolean saveFileVersions(String file, Collection<MethodSignature> values) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        refFile.mergeVersions(values);
        return true;
    }

    private void saveCandidateFileVersions(List<String> files, Collection<MethodSignature> values) {
        for(String file: files) {
            DatabaseReferenceFile refFile = usedSigFiles.get(file);
            if(refFile == null) {
                refFile = new DatabaseReferenceFile(file, null);
                tempSigFiles.put(file, refFile);
            }
            // no merge since we do not know the stable versions refFile.mergeVersions(values);
        }
    }

    public DatabaseReferenceFile getMatchedClassFile(IDexUnit dex, IDexClass cl, String className,
            DatabaseReference ref) {
        DatabaseReferenceFile refFile = getFileFromClass(dex, cl);
        if(refFile != null) {
            return refFile;
        }
        if(candidateMatchedClassesFile.containsKey(cl.getIndex())) {
            return null;
        }

        String f = null;
        List<String> fs = ref.getFilesContainingClass(className);
        if(fs == null || fs.isEmpty()) {
            return null;
        }
        if(fs.size() == 1) {
            f = fs.get(0);
            if(!usedSigFiles.containsKey(f)) {
                usedSigFiles.put(f, null);
            }
            addMatchedClassFiles(cl, f);
            return usedSigFiles.get(f);
        }
        List<String> candidates = new ArrayList<>();
        for(String cand: fs) {
            if(usedSigFiles.containsKey(cand)) {
                candidates.add(cand);
            }
        }
        if(candidates.size() == 1) {
            f = candidates.get(0);
            addMatchedClassFiles(cl, f);
            return usedSigFiles.get(f);
        }
        if(candidates.isEmpty()) {
            candidates = fs;
        }
        addCandidates(cl, candidates);
        return null;// maybe duplicated, wait for other part to decide
    }

    public List<MethodSignature> getSignatureLines(DatabaseReference ref, String file, String hashcode, boolean tight) {
        if(!usedSigFiles.containsKey(file)) {
            return ref.getSignatureLines(file, hashcode, tight);
        }
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        return ref.getSignatureLines(refFile, hashcode, tight);
    }

    public void addMatchedClass(IDexClass cl, String classname, List<String> files,
            Collection<MethodSignature> usedMethodSignatures) {
        if(matchedClasses.get(cl.getIndex()) != null) {
            logger.error("Conflict: Try to replace class %s", matchedClasses.get(cl.getIndex()));
            return;
        }
        if(matchedClasses.containsValue(classname)) {
            logger.error("Conflict: Try to bind class %s to %s which is already bind to ", classname,
                    cl.getSignature(false), cl.getSignature(true));
            return;
        }
        matchedClasses.put(cl.getIndex(), classname);
        removeClassFiles(cl);
        if(files != null && !files.isEmpty()) {
            if(files.size() == 1) {
                String file = files.get(0);
                saveFileVersions(file, usedMethodSignatures);
                addMatchedClassFiles(cl, file);
            }
            else {
                saveCandidateFileVersions(files, usedMethodSignatures);
                addCandidates(cl, files);
            }
        }
    }

    public void removeMatchedClass(int index) {
        matchedClasses.remove(index);
        matchedClassesFile.remove(index);
    }

    public String getMatchedClass(IDexClass cl) {
        return getMatchedClass(cl.getIndex());
    }

    public String getMatchedClass(int index) {
        return matchedClasses.get(index);
    }

    public boolean containsMatchedClass(IDexClass cl) {
        return containsMatchedClass(cl.getIndex());
    }

    public boolean containsMatchedClass(int index) {
        return matchedClasses.containsKey(index);
    }

    public boolean containsMatchedClassValue(String className) {
        return matchedClasses.containsValue(className);
    }

    public Map<Integer, String> getMatchedClasses() {
        return matchedClasses;
    }

    public Set<Entry<Integer, String>> entrySetMatchedClasses() {
        return matchedClasses.entrySet();
    }

    public void addMatchedMethod(IDexUnit unit, int index, MethodSignature sig) {
        addMatchedMethod(index, sig);

        IDexMethod m = unit.getMethod(index);
        bindMatchedSigMethod(unit, m, sig);
    }

    private void addMatchedMethod(int index, MethodSignature sig) {
        if(matchedMethods.get(index) != null) {
            logger.error("Conflict: Try to replace method %s", index);
            return;
        }
        matchedMethods.put(index, sig.getMname());
    }

    public void bindMatchedSigMethod(IDexUnit unit, IDexMethod m, MethodSignature ms) {
        matchedSigMethods.put(m.getIndex(), ms);
        // TODO update sigFile versions

        // post process: reinject parameters
        if(ms.getPrototype().isEmpty()) {
            // shorty or several matched: can not reinject classes anyway
            return;
        }

        IDexPrototype proto = unit.getPrototype(m.getPrototypeIndex());
        String prototypes = proto.generate(true);
        //if(prototypes.equals(sig.getPrototype())) {
        //    return;
        //}
        contextMatches.saveParamMatching(prototypes, ms.getPrototype(), ms.getCname(), ms.getMname());
    }

    public String getMatchedMethod(IDexMethod m) {
        return getMatchedMethod(m.getIndex());
    }

    public String getMatchedMethod(int index) {
        return matchedMethods.get(index);
    }

    public MethodSignature getMatchedSigMethod(IDexMethod m) {
        return getMatchedSigMethod(m.getIndex());
    }

    public MethodSignature getMatchedSigMethod(int index) {
        return matchedSigMethods.get(index);
    }

    public boolean containsMatchedMethod(IDexMethod m) {
        return containsMatchedMethod(m.getIndex());
    }

    public boolean containsMatchedMethod(int index) {
        return matchedMethods.containsKey(index);
    }

    public void removeMatchedMethod(int index) {
        matchedMethods.remove(index);
        matchedSigMethods.remove(index);
    }

    public Map<Integer, String> getMatchedMethods() {
        return matchedMethods;
    }

    public Set<Entry<Integer, String>> entrySetMatchedMethods() {
        return matchedMethods.entrySet();
    }

    public Set<Entry<Integer, MethodSignature>> entrySetMatchedSigMethods() {
        return matchedSigMethods.entrySet();
    }

}
