/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.model.SignatureFile;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.collect.CollectionUtil;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * Keep a library of files/versions used and try to get coherence with one version.
 * 
 * @author Cedric Lucas
 *
 */
public class FileMatches {

    /**
     * While not stable, we try to maintain usedSigFilesReduced (we could have several parallel
     * versions used for same library). Once stable, refuse incorrect versions
     */
    boolean stable = false;

    private Map<Integer, String> matchedClassesFile = new HashMap<>();

    /** Used files -> list of versions match (with occurrences) */
    Map<String, Map<String, Integer>> usedSigFiles = new HashMap<>();
    /** Used files -> list of versions */
    private Map<String, List<Set<String>>> usedSigFilesReduced = new HashMap<>();

    private boolean useReducedList() {
        return stable;
    }

    public String getFileFromClass(IDexClass dexClass) {
        return getFileFromClassId(dexClass.getIndex());
    }

    public String getFileFromClassId(int index) {
        return matchedClassesFile.get(index);
    }

    public void addMatchedClassFiles(IDexClass dexClass, String file) {
        matchedClassesFile.put(dexClass.getIndex(), file);
    }

    public String removeClassFiles(IDexClass dexClass) {
        return matchedClassesFile.remove(dexClass.getIndex());
    }

    public boolean addVersions(String file, Collection<MethodSignature> values) {
        if(!stable) {
            List<Set<String>> res = mergeVersions(usedSigFilesReduced.get(file), values, true);
            if(res == null) {
                return false;
            }
            usedSigFilesReduced.put(file, res);
        }
        usedSigFiles.put(file, mergeVersions(usedSigFiles.get(file), values));
        return true;
    }

    static Map<String, Integer> mergeVersions(Map<String, Integer> versionOccurences,
            Collection<MethodSignature> values) {
        if(versionOccurences == null) {
            versionOccurences = new HashMap<>();
        }
        for(MethodSignature value: values) {
            // put first as reference
            String[] versions = MethodSignature.getVersions(value);
            if(versions == null) {
                // sig1 or no version specified
                increment(versionOccurences, "all");
            }
            else {
                for(String v: versions) {
                    increment(versionOccurences, v);
                }
            }
        }
        return versionOccurences;
    }

    private static List<Set<String>> mergeVersions(List<Set<String>> reducedVersions,
            Collection<MethodSignature> values, boolean mergeTypes) {
        if(reducedVersions == null) {
            reducedVersions = new ArrayList<>();
        }
        List<String> allVersionList = new ArrayList<>();
        boolean invalidSignature = false;
        for(MethodSignature value: values) {
            // put first as reference
            String[] versions = MethodSignature.getVersions(value);
            if(versions == null) {
                // sig1 or no version specified, no need to reduce
            }
            else {
                Set<String> versionList = new HashSet<>();
                for(String v: versions) {
                    if(mergeTypes) {
                        versionList.add(v.replace("_d8r", "").replace("_d8d", "").replace("_d8", ""));
                    }
                    else {
                        versionList.add(v);
                    }
                }
                if(allVersionList.isEmpty()) {
                    allVersionList.addAll(versionList);
                }
                else {
                    allVersionList = CollectionUtil.intersection(allVersionList, new ArrayList<>(versionList));
                    if(allVersionList.isEmpty()) {
                        invalidSignature = true;
                        break;
                    }
                }
            }
        }
        if(invalidSignature) {
            return null;
        }
        int i = 0;
        boolean found = false;
        for(Set<String> versionSet: reducedVersions) {
            for(String v: allVersionList) {
                if(versionSet.contains(v)) {
                    // ok, here we found that current version match
                    found = true;
                    break;
                }
            }
            if(found) {
                break;
            }
            // if not found, this means that there is no set defined for this version
            i++;
        }

        if(found) {
            List<String> newSet = CollectionUtil.intersection(allVersionList, new ArrayList<>(reducedVersions.get(i)));
            reducedVersions.set(i, new HashSet<>(newSet));
        }
        else {
            reducedVersions.add(new HashSet<>(allVersionList));
        }
        return reducedVersions;
    }

    static void increment(Map<String, Integer> versionOccurences, String key) {
        Integer val = versionOccurences.get(key);
        if(val == null) {
            versionOccurences.put(key, 1);
        }
        else {
            versionOccurences.put(key, val + 1);
        }
    }

    public List<List<String>> getOrderedVersions(String f) {
        Map<String, Integer> versions = usedSigFiles.get(f);
        if(versions == null) {
            return new ArrayList<>();
        }
        List<List<String>> res = orderVersions(versions);
        if(hasNoVersion(res)) {
            return new ArrayList<>();
        }
        return res;
    }


    String getMatchedClassFile(IDexClass cl, String className, DatabaseReference ref) {
        String f = getFileFromClass(cl);
        if(f != null) {
            return f;
        }
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
        SignatureFile sigFile = ref.getSignatureFile(f);
        List<MethodSignature> compatibleSignatures = sigFile.getSignaturesForClassname(className);
        Map<String, Integer> versions = usedSigFiles.get(f);
        List<List<String>> preferedOrderList = orderVersions(versions);
        int level = 0;
        if(hasNoVersion(preferedOrderList)) {
            return level;
        }
        for(List<String> preferedOrder: preferedOrderList) {
            for(String prefered: preferedOrder) {
                for(MethodSignature sig: compatibleSignatures) {
                    if(Arrays.asList(sig.getVersions()).contains(prefered)) {
                        return level;
                    }
                }
            }
            level++;
        }
        return -1;
    }

    boolean hasNoVersion(List<List<String>> preferedOrderList) {
        return preferedOrderList.size() == 1 && preferedOrderList.get(0).size() == 1
                && preferedOrderList.get(0).get(0).equals("all");
    }

    List<List<String>> orderVersions(Map<String, Integer> versions) {
        Map<Integer, List<String>> versionsRev = versions.entrySet().stream().collect(
                Collectors.groupingBy(Map.Entry::getValue, Collectors.mapping(Map.Entry::getKey, Collectors.toList())));
        versionsRev = new TreeMap<>(versionsRev);
        List<List<String>> ordered = new ArrayList<>();
        VersionComparator vsCmp = new VersionComparator();
        for(Entry<Integer, List<String>> entry: versionsRev.entrySet()) {
            List<String> vs = new ArrayList<>(entry.getValue());
            Collections.sort(vs, vsCmp);
            Collections.reverse(vs);
            ordered.add(vs);
        }
        Collections.reverse(ordered);
        if(useReducedList() && usedSigFilesReduced.size() == 1) {
            // only one version as reference
            List<List<String>> newOrdered = new ArrayList<>();
            newOrdered.add(ordered.get(0));
            return newOrdered;
        }
        return ordered;
    }

    private static class VersionComparator implements Comparator<String> {
        @Override
        public int compare(String v1, String v2) {
            boolean v1Test = Strings.contains(v1.toLowerCase(), "rc", "alpha", "beta", "snapshot");
            boolean v2Test = Strings.contains(v1.toLowerCase(), "rc", "alpha", "beta", "snapshot");
            if(v1Test) {
                return v2Test ? v1.compareTo(v2): 1;
            }
            return v2Test ? -1: v1.compareTo(v2);
        }
    }

    public List<MethodSignature> filterMatchingSignatures(String f, List<MethodSignature> candidates) {
        List<List<String>> preferedOrder = getOrderedVersions(f);
        List<MethodSignature> newCandidates = new ArrayList<>();
        if(preferedOrder == null || preferedOrder.isEmpty()) {
            return newCandidates;
        }
        for(MethodSignature sig: candidates) {
            for(String prefered: preferedOrder.get(0)) {
                if(Arrays.asList(sig.getVersions()).contains(prefered)) {
                    newCandidates.add(sig);
                    break; // no need to check other versions
                }
            }
        }
        return newCandidates;
    }

    public static Set<String> getVersions(IDexClass parentClass, Map<Integer, MethodSignature> matchedSigMethods) {
        List<? extends IDexMethod> methods = parentClass.getMethods();
        List<Set<String>> reducedVersions = null;
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal()) {
                continue;
            }
            if(matchedSigMethods.containsKey(eMethod.getIndex())) {
                MethodSignature mSig = matchedSigMethods.get(eMethod.getIndex());
                reducedVersions = mergeVersions(reducedVersions, Arrays.asList(mSig), false);
            }
        }
        if(reducedVersions != null && reducedVersions.size() == 1) {
            return reducedVersions.get(0);
        }
        return null;
    }

}
