/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;

/**
 * Keep a library of files/versions used and try to get coherence with one version.
 * 
 * @author Cedric Lucas
 *
 */
public class FileMatches {

    private Map<Integer, DatabaseReferenceFile> matchedClassesFile = new HashMap<>();

    /** Used files -> list of versions match (with occurrences) */
    private Map<String, DatabaseReferenceFile> usedSigFiles = new HashMap<>();

    public Set<String> getSignatureFileUsed() {
        return usedSigFiles.keySet();
    }

    public Set<Entry<String, DatabaseReferenceFile>> getSignatureFileEntrySet() {
        return usedSigFiles.entrySet();
    }

    public boolean isSignatureFileUsed(String f) {
        return usedSigFiles.containsKey(f);
    }

    public DatabaseReferenceFile getFileFromClass(IDexClass dexClass) {
        return getFileFromClassId(dexClass.getIndex());
    }

    public DatabaseReferenceFile getFileFromClassId(int index) {
        return matchedClassesFile.get(index);
    }

    public void addMatchedClassFiles(IDexClass dexClass, String file) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        matchedClassesFile.put(dexClass.getIndex(), refFile);
    }

    public DatabaseReferenceFile removeClassFiles(IDexClass dexClass) {
        return matchedClassesFile.remove(dexClass.getIndex());
    }

    public boolean addVersions(String file, Collection<MethodSignature> values) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        refFile.mergeVersions(values);
        return true;
    }

    public List<List<String>> getOrderedVersions(String f) {
        return getOrderedVersions(usedSigFiles.get(f));
    }

    public List<List<String>> getOrderedVersions(DatabaseReferenceFile refFile) {
        if(refFile == null) {
            return new ArrayList<>();
        }
        return refFile.getOrderedVersions();
    }


    public String getMatchedClassFile(IDexClass cl, String className, DatabaseReference ref) {
        DatabaseReferenceFile refFile = getFileFromClass(cl);
        if(refFile != null) {
            return refFile.file;
        }
        String f = null;
        List<String> fs = ref.getFilesContainingClass(className);
        if(fs == null || fs.isEmpty()) {
            return null;
        }
        if(fs.size() == 1) {
            f = fs.get(0);
            addMatchedClassFiles(cl, f);
            if(!usedSigFiles.containsKey(f)) {
                usedSigFiles.put(f, null);
            }
            return f;
        }
        List<String> candidates = new ArrayList<>();
        for(String cand: fs) {
            if(usedSigFiles.containsKey(cand)) {
                candidates.add(cand);
            }
        }
        if(candidates.isEmpty()) {
            return fs.get(0);
        }
        if(candidates.size() == 1) {
            f = candidates.get(0);
            addMatchedClassFiles(cl, f);
            return f;
        }
        List<String> newcandidates = new ArrayList<>();
        int bestLevel = -1;
        for(String candidate: candidates) {
            int level = getLevel(ref, candidate, className);
            if(level >= 0) {
                if(bestLevel < 0) {
                    bestLevel = level;
                    newcandidates.add(candidate);
                }
                else if(level < bestLevel) {
                    newcandidates.clear();
                    bestLevel = level;
                    newcandidates.add(candidate);
                }
                else if(level == bestLevel) {
                    newcandidates.add(candidate);
                }
            }
        }
        if(newcandidates.size() == 1) {
            f = newcandidates.get(0);
            addMatchedClassFiles(cl, f);
            return f;
        }
        return null;// maybe duplicated, wait for other part to decide
    }

    private int getLevel(DatabaseReference ref, String f, String className) {
        List<MethodSignature> compatibleSignatures = ref.getSignaturesForClassname(f, className, true);
        DatabaseReferenceFile refFile = usedSigFiles.get(f);
        List<List<String>> preferedOrderList = refFile.getOrderedVersions();
        int level = 0;
        if(preferedOrderList.isEmpty()) {
            return level;
        }
        for(List<String> preferedOrder: preferedOrderList) {
            for(String prefered: preferedOrder) {
                for(MethodSignature sig: compatibleSignatures) {
                    String[] versionsArray = sig.getVersions();
                    if(versionsArray == null) {
                        return level;
                    }
                    if(Arrays.asList(versionsArray).contains(prefered)) {
                        return level;
                    }
                }
            }
            level++;
        }
        return -1;
    }

    public List<MethodSignature> getSignatureLines(DatabaseReference ref, String file, String hashcode, boolean tight) {
        if(!usedSigFiles.containsKey(file)) {
            return ref.getSignatureLines(file, hashcode, tight);
        }
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        return ref.getSignatureLines(refFile, hashcode, tight);
    }
}
