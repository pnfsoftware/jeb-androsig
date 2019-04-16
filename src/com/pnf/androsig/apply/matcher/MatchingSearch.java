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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
class MatchingSearch {

    class InnerMatch {
        String className;
        Map<Integer, MethodSignature> classPathMethod = new HashMap<>();
        String file;
        Set<String> versions = new HashSet<>();
        List<Integer> doNotRenameIndexes = new ArrayList<>();

        public void validateVersions() {
            Map<String, Integer> versionOccurences = FileMatches.mergeVersions(null, classPathMethod.values());
            List<List<String>> preferedOrderList = fileMatches.orderVersions(versionOccurences);
            versions.addAll(preferedOrderList.get(0));
            // FIXME not only the preferred order: 2 preferred orders must be equally present
            List<Integer> illegalMethods = new ArrayList<>();
            for(Entry<Integer, MethodSignature> method: classPathMethod.entrySet()) {
                if(method.getValue().getVersions() == null) {
                    continue;
                }
                boolean found = false;
                for(String v: method.getValue().getVersions()) {
                    if(versions.contains(v)) {
                        found = true;
                        break;
                    }
                }
                if(!found) {
                    illegalMethods.add(method.getKey());
                }
            }
            for(Integer illegal: illegalMethods) {
                classPathMethod.remove(illegal);
            }
        }
    }

    private IDexUnit dex;
    private DexHashcodeList dexHashCodeList;
    private DatabaseReference ref;
    private DatabaseMatcherParameters params;
    private FileMatches fileMatches;
    private Map<Integer, Map<Integer, Integer>> apkCallerLists;
    private boolean firstRound;

    private Map<String, Map<String, InnerMatch>> fileCandidates = new HashMap<>(); // file -> (classname->count)

    public MatchingSearch(IDexUnit dex, DexHashcodeList dexHashCodeList, DatabaseReference ref,
            DatabaseMatcherParameters params, FileMatches fileMatches,
            Map<Integer, Map<Integer, Integer>> apkCallerLists, boolean firstRound) {
        this.dex = dex;
        this.dexHashCodeList = dexHashCodeList;
        this.ref = ref;
        this.params = params;
        this.fileMatches = fileMatches;
        this.apkCallerLists = apkCallerLists;
        this.firstRound = firstRound;
    }

    // TODO filter versions on ref.getSignatureLines when possible

    private List<MethodSignature> getInnerClassSignatureLines(String file, String mhash, boolean tight,
            String innerClass) {
        List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash, tight);
        if(sigLine != null) {
            sigLine = sigLine.stream().filter(s -> s.getCname().startsWith(innerClass)).collect(Collectors.toList());
        }
        return sigLine;
    }

    public void processInnerClass(String file, Map<Integer, String> matchedMethods, List<? extends IDexMethod> methods,
            String innerClass, int innerLevel, List<MethodSignature> compatibleSignatures) {
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                continue;
            }
            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            List<MethodSignature> sigLine = null;
            if(mhash_tight != null) {
                sigLine = getInnerClassSignatureLines(file, mhash_tight, true, innerClass);
            }
            if(!firstRound) {
                if(sigLine == null || sigLine.isEmpty()) {
                    // may be done even if tight is found
                    String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                    if(mhash_loose != null) {
                        sigLine = getInnerClassSignatureLines(file, mhash_loose, false, innerClass);
                    }
                }
                if(sigLine == null || sigLine.isEmpty()) {
                    // look for candidates based on signature match
                    IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = null;//dex.getStrings().get(proto.getShortyIndex()).getValue();
                    sigLine = compatibleSignatures.stream()
                            .filter(s -> isCompatibleSignature(eMethod, prototypes, true, shorty, false, s))
                            .collect(Collectors.toList());
                }
            }
            if(sigLine == null || sigLine.isEmpty()) {
                continue;
            }

            Map<String, InnerMatch> classes = fileCandidates.get(file);
            if(classes == null) {
                classes = new HashMap<>();
                fileCandidates.put(file, classes);
            }
            saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
        }
    }

    public void processClass(Map<Integer, String> matchedMethods, List<? extends IDexMethod> methods, int innerLevel) {
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                continue;
            }

            // The second round
            //if(!firstRound && !apkCallerLists.containsKey(eMethod.getIndex())) {
            //    continue;
            //}

            List<? extends IInstruction> instructions = eMethod.getInstructions();
            if(instructions == null) {
                continue;
            }
            if(instructions.size() <= params.methodSizeBar) {
                continue;
            }

            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            if(mhash_tight == null) {
                continue;
            }
            List<String> candidateFiles = ref.getFilesContainingTightHashcode(mhash_tight);
            if(candidateFiles != null) {
                for(String file: candidateFiles) {
                    List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_tight, true);
                    Map<String, InnerMatch> classes = fileCandidates.get(file);
                    if(classes == null) {
                        classes = new HashMap<>();
                        fileCandidates.put(file, classes);
                    }
                    saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
                }
            }
            else if(!firstRound) {
                // may be done even if tight is found
                String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                if(mhash_loose == null) {
                    continue;
                }
                candidateFiles = ref.getFilesContainingLooseHashcode(mhash_loose);
                if(candidateFiles != null) {
                    for(String file: candidateFiles) {
                        List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_loose, false);
                        Map<String, InnerMatch> classes = fileCandidates.get(file);
                        if(classes == null) {
                            classes = new HashMap<>();
                            fileCandidates.put(file, classes);
                        }
                        saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file, innerLevel);
                    }
                }
            }
        }
    }

    private void saveTemporaryCandidate(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file, int innerLevel) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<MethodSignature> realCandidates = elts.stream()
                .filter(strArray -> MethodSignature.getShorty(strArray).equals(shorty)
                        && MethodSignature.getPrototype(strArray).equals(prototype))
                .collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            List<MethodSignature> strArrays = mergeSignaturesPerClass(realCandidates);
            for(MethodSignature strArray: strArrays) {
                String className = MethodSignature.getClassname(strArray);
                if(DexUtilLocal.getInnerClassLevel(className) != innerLevel) {
                    continue;
                }
                InnerMatch inner = classes.get(className);
                if(inner == null) {
                    inner = new InnerMatch();
                    inner.className = className;
                    inner.file = file;
                }
                inner.classPathMethod.put(eMethod.getIndex(), strArray);
                if(realCandidates.size() > 1) {
                    // we can not establish which method is the good one
                    // however, it is good to report that a matching was found (for percentage matching instructions
                    inner.doNotRenameIndexes.add(eMethod.getIndex());
                }
                classes.put(className, inner);
            }
        }
    }

    public MethodSignature findMethodMatch(String file, String classPath,
            Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod, boolean allowEmptyMName) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
        String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
        if(mhash_tight == null) {
            return null;
        }
        return findMethodMatch(file, mhash_tight, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod,
                allowEmptyMName);
    }

    public MethodSignature findMethodMatch(String file, String mhash_tight, String prototypes, String shorty,
            String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod,
            boolean allowEmptyMName) {
        MethodSignature strArray = null;
        List<MethodSignature> sigs = ref.getSignatureLines(file, mhash_tight, true);
        if(sigs != null) {
            strArray = findMethodName(dex, sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
        }
        if(strArray == null || (!allowEmptyMName && strArray.getMname().isEmpty())) {
            String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
            sigs = ref.getSignatureLines(file, mhash_loose, false);
            if(sigs != null) {
                strArray = findMethodName(dex, sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
            }
        }
        return strArray;
    }

    MethodSignature findMethodName(IDexUnit dex, List<MethodSignature> sigs, String classPath,
            Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
        return findMethodName(dex, sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
    }

    MethodSignature findMethodName(IDexUnit dex, List<MethodSignature> sigs, String proto, String shorty,
            String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        MethodSignature sig = findMethodName(dex, sigs, proto, true, classPath, alreadyProcessedMethods, eMethod);
        if(sig != null) {
            return sig;
        }
        return findMethodName(dex, sigs, shorty, false, classPath, alreadyProcessedMethods, eMethod);
    }

    private MethodSignature findMethodName(IDexUnit dex, List<MethodSignature> sigs, String proto,
            boolean prototype, String classPath, Collection<MethodSignature> alreadyProcessedMethods,
            IDexMethod eMethod) {
        List<MethodSignature> results = new ArrayList<>();
        proto: for(MethodSignature strArray: sigs) {
            if(!isCompatibleSignature(eMethod, proto, prototype, proto, !prototype, strArray)) {
                continue;
            }
            if(!MethodSignature.getClassname(strArray).equals(classPath)) {
                continue;
            }
            for(MethodSignature alreadyProcessed: alreadyProcessedMethods) {
                if((prototype ? alreadyProcessed.getPrototype().equals(strArray.getPrototype())
                        : alreadyProcessed.getShorty().equals(strArray.getShorty()))
                        && alreadyProcessed.getMname().equals(strArray.getMname())) {
                    // method has already a match
                    continue proto;
                }
            }
            results.add(strArray);
        }
        if(results.size() == 1) {
            return results.get(0);
        }
        else if(results.size() > 1) {
            filterList(dex, eMethod, results);
            if(results.size() == 1) {
                return results.get(0);
            }
            return MatchingSearch.mergeSignature(results);
        }
        return null;
    }

    private boolean isCompatibleSignature(IDexMethod eMethod, String prototypes, boolean checkPrototypes, String shorty,
            boolean checkShorty, MethodSignature strArray) {
        if(checkPrototypes && !strArray.getPrototype().equals(prototypes)) {
            return false;
        }
        if(checkShorty && !strArray.getShorty().equals(shorty)) {
            return false;
        }
        // init/clinit can not be changed, but is a good indicator for matching
        String methodName = eMethod.getName(true);
        if(methodName.equals("<init>")) {
            if(!strArray.getMname().equals("<init>")) {
                return false;
            }
        }
        else if(methodName.equals("<clinit>")) {
            if(!strArray.getMname().equals("<clinit>")) {
                return false;
            }
        }
        else if(strArray.getMname().equals("<init>") || strArray.getMname().equals("<clinit>")) {
            return false;
        }
        return true;
    }

    private void filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results) {
        // only on post processing
        // firstly, filter versions
        String f = fileMatches.getFileFromClass(eMethod.getClassType().getImplementingClass());
        if(f == null) {
            return; // wait for post process to retrieve correct file
        }
        Set<MethodSignature> filtered = new HashSet<>();
        List<List<String>> preferedOrderList = fileMatches.getOrderedVersions(f);
        boolean found = false;
        for(List<String> preferedOrder: preferedOrderList) {
            // save level signatures
            for(String prefered: preferedOrder) {
                for(MethodSignature sig: results) {
                    if(Arrays.asList(sig.getVersions()).contains(prefered)) {
                        found = true;
                        filtered.add(sig);
                    }
                }
            }
            if(found) {
                break;
            }
        }
        if(!filtered.isEmpty()) {
            results.clear();
            results.addAll(filtered);
            if(results.size() == 1) {
                return;
            }
        }

        // secondly, filter by caller
        if(apkCallerLists.isEmpty()) {
            return;
        }
        Map<Integer, Integer> callers = apkCallerLists.get(eMethod.getIndex());
        if(callers == null) {
            return;
        }
        // caller may not be referenced in lib
        filtered.clear();
        outer: for(MethodSignature sig: results) {
            Map<String, Integer> targets = new HashMap<>(sig.getTargetCaller());
            if(targets.isEmpty()) {
                continue;
            }
            for(Entry<Integer, Integer> c: callers.entrySet()) {
                // is there a method matching?
                // FIXME allow partial matching? maybe in later steps
                IDexMethod cMethod = dex.getMethod(c.getKey());
                Integer occ = targets.remove(cMethod.getSignature(true));
                if(occ == null || occ != c.getValue()) {
                    //not the same method
                    continue outer;
                }
            }
            filtered.add(sig);
        }
        if(!filtered.isEmpty()) {
            results.clear();
            results.addAll(filtered);
        }
    }

    static MethodSignature mergeSignature(List<MethodSignature> results) {
        if(results == null || results.isEmpty()) {
            return null;
        }
        if(results.size() == 1) {
            return results.get(0);
        }
        String[] result = new String[9];
        for(int i = 0; i < 5; i++) {
            for(MethodSignature ress: results) {
                String[] res = ress.toTokens();
                if(i >= res.length) {
                    continue;
                }
                if(result[i] == null) {
                    result[i] = res[i];
                }
                else if(!result[i].equals(res[i])) {
                    result[i] = ""; // two lines differ here: may loose callers
                    if(i == 1) {
                        // String methodMatch = result[i] + " OR " + res[i];
                        // logger.debug("%s: There are several methods matching for signature %s: %s", ress.getCname(),
                        //         ress.getPrototype(), methodMatch);
                    }
                    break;
                }
            }
        }
        // merge versions
        Set<String> versions = new HashSet<>();
        for(MethodSignature value: results) {
            // put first as reference
            String[] vArray = MethodSignature.getVersions(value);
            if(vArray != null) {
                for(String version: vArray) {
                    versions.add(version);
                }
            }
        }
        return new MethodSignature(MethodSignature.getClassname(result), MethodSignature.getMethodName(result),
                MethodSignature.getShorty(result), MethodSignature.getPrototype(result), result[4],
                Strings.join(";", versions));
    }

    static List<MethodSignature> mergeSignaturesPerClass(List<MethodSignature> results) {
        if(results.size() < 2) {
            return results;
        }
        Map<String, List<MethodSignature>> sigs = new HashMap<>();
        for(MethodSignature result: results) {
            String className = result.getCname();
            List<MethodSignature> values = sigs.get(className);
            if(values == null) {
                values = new ArrayList<>();
                sigs.put(className, values);
            }
            values.add(result);
        }
        List<MethodSignature> merged = new ArrayList<>();
        for(List<MethodSignature> values: sigs.values()) {
            merged.add(mergeSignature(values));
        }
        return merged;
    }

    public boolean isEmpty() {
        return fileCandidates.isEmpty();
    }

    public Set<Entry<String, Map<String, InnerMatch>>> entrySet() {
        return fileCandidates.entrySet();
    }

}
