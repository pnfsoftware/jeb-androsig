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
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.collect.CollectionUtil;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
public class MatchingSearch {
    static class InnerMatch {
        String className;
        Map<Integer, MethodSignature> classPathMethod = new HashMap<>();
        String file;
        List<Integer> doNotRenameIndexes = new ArrayList<>();
        public boolean oneMatch;
        public DatabaseReferenceFile refFile;

        public void validateMethods() {
            Set<String> duplicated = new HashSet<>();
            Set<String> sigSets = new HashSet<>();
            for(Entry<Integer, MethodSignature> sig: classPathMethod.entrySet()) {
                if(!sigSets.contains(sig.getValue().getMname())) {
                    sigSets.add(sig.getValue().getMname());
                }
                else {
                    duplicated.add(sig.getValue().getMname());
                }
            }
            if(duplicated.isEmpty()) {
                return;
            }

            // some methods share same name. Compare prototypes
            Map<String, List<Integer>> duplicatedKeys = new HashMap<>();
            for(Entry<Integer, MethodSignature> sig: classPathMethod.entrySet()) {
                if(duplicated.contains(sig.getValue().getMname())) {
                    List<Integer> val = duplicatedKeys.get(sig.getValue().getMname());
                    if(val == null) {
                        val = new ArrayList<>();
                        duplicatedKeys.put(sig.getValue().getMname(), val);
                    }
                    val.add(sig.getKey());
                }
            }
            for(Entry<String, List<Integer>> dup: duplicatedKeys.entrySet()) {
                boolean unsafe = false;
                for(int i = 0; i < dup.getValue().size(); i++) {
                    Integer currentKey = dup.getValue().get(i);
                    if(Strings.isBlank(classPathMethod.get(currentKey).getPrototype())) {
                        unsafe = true;
                        break;
                    }
                    for(int j = i + 1; j < dup.getValue().size(); j++) {
                        Integer vsKey = dup.getValue().get(j);
                        if(classPathMethod.get(currentKey).getPrototype()
                                .equals(classPathMethod.get(vsKey).getPrototype())) {
                            // same prototype
                            unsafe = true;
                            break;
                        }
                    }
                    if(unsafe) {
                        break;
                    }
                }
                if(unsafe) {
                    // remove duplicates
                    doNotRenameIndexes.addAll(dup.getValue());
                }
            }
        }

        public void validateVersions() {
            refFile = new DatabaseReferenceFile(file, null);
            refFile.mergeVersions(classPathMethod.values());
            if(refFile.hasNoVersion()) {
                return;
            }
            List<List<String>> preferedOrderList = refFile.getOrderedVersions();
            if(preferedOrderList == null || preferedOrderList.isEmpty()) {
                return; //versionless
            }
            List<String> versions = preferedOrderList.get(0);
            List<Integer> illegalMethods = new ArrayList<>();
            for(Entry<Integer, MethodSignature> method: classPathMethod.entrySet()) {
                String[] versionsArray = method.getValue().getVersions();
                if(versionsArray == null) {
                    continue;
                }
                boolean found = false;
                for(String v: versionsArray) {
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
            if(!refFile.getMergedVersions().contains(versions.get(0))) {
                // regenerate, wrong base
                refFile = new DatabaseReferenceFile(file, null);
                refFile.mergeVersions(classPathMethod.values());
            }
        }
    }

    private IDatabaseMatcher dbMatcher;
    private IDexUnit dex;
    private DexHashcodeList dexHashCodeList;
    private DatabaseReference ref;
    private DatabaseMatcherParameters params;
    private FileMatches fileMatches;
    private List<IAndrosigModule> modules;
    private boolean firstRound;
    private boolean firstPass;
    private boolean safe;

    private Map<String, Map<String, InnerMatch>> fileCandidates = new HashMap<>(); // file -> (classname->count)

    public MatchingSearch(IDatabaseMatcher dbMatcher, IDexUnit dex, DexHashcodeList dexHashCodeList,
            DatabaseReference ref, DatabaseMatcherParameters params, FileMatches fileMatches,
            List<IAndrosigModule> modules, boolean firstRound, boolean firstPass, boolean safe) {
        this.dbMatcher = dbMatcher;
        this.dex = dex;
        this.dexHashCodeList = dexHashCodeList;
        this.ref = ref;
        this.params = params;
        this.fileMatches = fileMatches;
        this.modules = modules;
        this.firstRound = firstRound;
        this.firstPass = firstPass;
        this.safe = safe;
    }

    private List<MethodSignature> getInnerClassSignatureLines(DatabaseReferenceFile file, String mhash, boolean tight,
            String innerClass) {
        List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash, tight);
        if(sigLine != null) {
            sigLine = sigLine.stream().filter(s -> s.getCname().startsWith(innerClass)).collect(Collectors.toList());
        }
        return sigLine;
    }

    public void processInnerClass(DatabaseReferenceFile file, Map<Integer, String> matchedMethods, IDexClass eClass,
            List<? extends IDexMethod> methods, String innerClass, int innerLevel,
            List<MethodSignature> compatibleSignatures) {
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal()) {
                continue;
            }

            List<? extends IInstruction> instructions = eMethod.getInstructions();
            boolean instructionBarReached = instructions == null ? false: instructions.size() > params.methodSizeBar;
            if(!instructionBarReached) {
                instructionBarReached = !eClass.getSupertypes().get(0).getSignature(true).equals("Ljava/lang/Object;");
            }
            List<MethodSignature> sigLine = null;
            if(instructionBarReached) {
                String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                if(mhash_tight != null) {
                    sigLine = getInnerClassSignatureLines(file, mhash_tight, true, innerClass);
                }
            }
            if(!firstRound) {
                if((sigLine == null || sigLine.isEmpty()) && instructionBarReached) {
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
                    String params1 = DexUtilLocal.extractParamsFromSignature(prototypes);
                    List<String> paramList = DexUtilLocal.parseSignatureParameters(params1);
                    if(paramList.isEmpty() || (paramList.size() == 1 && paramList.get(0).length() == 1)) {
                        String mname = eMethod.getName(true);
                        sigLine = sigLine.stream().filter(s -> s.getMname().equals(mname)).collect(Collectors.toList());
                    }
                }
            }
            if(sigLine == null || sigLine.isEmpty()) {
                continue;
            }
            if(matchedMethods.containsKey(eMethod.getIndex())) {
                String mname = matchedMethods.get(eMethod.getIndex());
                sigLine = sigLine.stream().filter(s -> mname.equals(s.getMname())).collect(Collectors.toList());
                if(sigLine.isEmpty()) {
                    continue;
                }
            }

            Map<String, InnerMatch> classes = fileCandidates.get(file.file);
            if(classes == null) {
                classes = new HashMap<>();
                fileCandidates.put(file.file, classes);
            }
            saveTemporaryCandidate(eMethod, sigLine, firstRound, classes, file.file, innerLevel);
        }
    }

    public boolean processClass(IMatcherValidation validation, Map<Integer, String> matchedMethods,
            IDexClass eClass, List<? extends IDexMethod> methods, int innerLevel) {
        List<String> validFiles = getValidFiles(validation, eClass, methods);
        return processClass(validation, matchedMethods, eClass, methods, innerLevel, validFiles);
    }

    public boolean processClass(IMatcherValidation validation, Map<Integer, String> matchedMethods, IDexClass eClass,
            List<? extends IDexMethod> methods, int innerLevel, List<String> validFiles) {
        // quick win: to avoid loading all files, consider first if valid in best case
        // meaning: if all methods really match (without looking at prototypes)
        if(!firstRound && !firstPass && validFiles.size() > 1) {
            // restrict list of available files
            validFiles = CollectionUtil.intersection(validFiles, new ArrayList<>(fileMatches.getSignatureFileUsed()));
        }
        if(validFiles.isEmpty() && !firstRound) {
            return false;
        }

        List<IDexMethod> easyMatches = new ArrayList<>();
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal()) {
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
                candidateFiles = CollectionUtil.intersection(validFiles, candidateFiles);
                if(firstRound && candidateFiles.size() > 10) {
                    // do not process here: will be considered as small method
                    easyMatches.add(eMethod);
                    continue;
                }

                for(String file: candidateFiles) {
                    List<MethodSignature> sigLines = fileMatches.getSignatureLines(ref, file, mhash_tight, true);
                    if(sigLines == null || sigLines.isEmpty()) {
                        continue;
                    }
                    if (matchedMethods.containsKey(eMethod.getIndex())) {
                        String mname = matchedMethods.get(eMethod.getIndex());
                        sigLines = sigLines.stream().filter(s -> mname.equals(s.getMname())).collect(Collectors.toList());
                        if(sigLines.isEmpty()) {
                            continue;
                        }
                    }
                    Map<String, InnerMatch> classes = fileCandidates.get(file);
                    if(classes == null) {
                        classes = new HashMap<>();
                        fileCandidates.put(file, classes);
                    }
                    saveTemporaryCandidate(eMethod, sigLines, firstRound, classes, file, innerLevel);
                    if(classes.isEmpty()) {
                        fileCandidates.remove(file);
                    }
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
                        if(!validFiles.contains(file)) {
                            continue;
                        }
                        List<MethodSignature> sigLines = fileMatches.getSignatureLines(ref, file, mhash_loose, false);
                        if(sigLines == null || sigLines.isEmpty()) {
                            continue;
                        }
                        if(matchedMethods.containsKey(eMethod.getIndex())) {
                            String mname = matchedMethods.get(eMethod.getIndex());
                            sigLines = sigLines.stream().filter(s -> mname.equals(s.getMname()))
                                    .collect(Collectors.toList());
                            if(sigLines.isEmpty()) {
                                continue;
                            }
                        }
                        Map<String, InnerMatch> classes = fileCandidates.get(file);
                        if(classes == null) {
                            classes = new HashMap<>();
                            fileCandidates.put(file, classes);
                        }
                        saveTemporaryCandidate(eMethod, sigLines, firstRound, classes, file, innerLevel);
                        if(classes.isEmpty()) {
                            fileCandidates.remove(file);
                        }
                    }
                }
            }
        }
        return true;
    }

    private List<String> getValidFiles(IMatcherValidation validation, IDexClass eClass,
            List<? extends IDexMethod> methods) {
        Map<String, List<Integer>> methodsPerFile = new HashMap<>();
        Map<String, List<Integer>> methodsPerFileSmalls = new HashMap<>();
        for(IDexMethod eMethod: methods) {
            if(!eMethod.isInternal()) {
                continue;
            }

            List<? extends IInstruction> instructions = eMethod.getInstructions();
            if(instructions == null) {
                continue;
            }

            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
            if(mhash_tight == null) {
                continue;
            }
            List<String> candidateFiles = ref.getFilesContainingTightHashcode(mhash_tight);
            if(candidateFiles == null && !firstRound) {
                String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                if(mhash_loose == null) {
                    continue;
                }
                candidateFiles = ref.getFilesContainingLooseHashcode(mhash_loose);
            }
            if(candidateFiles == null || candidateFiles.isEmpty()) {
                continue;
            }
            Map<String, List<Integer>> indexMap = methodsPerFile;
            if(/*(!firstRound && !firstPass) &&*/ instructions.size() <= params.methodSizeBar) {
                indexMap = methodsPerFileSmalls;
            }
            for(String file: candidateFiles) {
                List<Integer> methodIds = indexMap.get(file);
                if(methodIds == null) {
                    methodIds = new ArrayList<>();
                    indexMap.put(file, methodIds);
                }
                methodIds.add(eMethod.getIndex());
            }
        }
        List<String> validFiles = new ArrayList<>();
        // Very important: do not consider Classes with only small method matches
        for(Entry<String, List<Integer>> entry: methodsPerFile.entrySet()) {
            List<Integer> allMethodsMatch = new ArrayList<>();
            allMethodsMatch.addAll(entry.getValue());
            List<Integer> smalls = methodsPerFileSmalls.get(entry.getKey());
            if(smalls != null) {
                allMethodsMatch.addAll(smalls);
            }
            if(!firstRound || validation.f(dex, eClass, allMethodsMatch) == null) {
                // would ignore small methods
                validFiles.add(entry.getKey());
            }
        }
        return validFiles;
    }

    private void saveTemporaryCandidate(IDexMethod eMethod, List<MethodSignature> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file, int innerLevel) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<MethodSignature> realCandidates = elts.stream()
                .filter(strArray -> strArray.getShorty().equals(shorty) && strArray.getPrototype().equals(prototype))
                .collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            List<MethodSignature> strArrays = mergeSignaturesPerClass(realCandidates);
            for(MethodSignature strArray: strArrays) {
                String className = strArray.getCname();
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
                    // however, it is good to report that a matching was found (for percentage matching instructions)
                    inner.doNotRenameIndexes.add(eMethod.getIndex());
                }
                classes.put(className, inner);
            }
        }
    }

    public List<MethodSignature> getSignaturesForClassname(DatabaseReferenceFile file, String className,
            boolean exactName, IDexMethod eMethod) {
        List<MethodSignature> sigs = ref.getSignaturesForClassname(file, className, true);
        List<? extends IInstruction> instructions = eMethod.getInstructions();
        // filter abstracts or not
        return sigs = sigs.stream().filter(s -> instructions == null ? s.isEmptyOp(): !s.isEmptyOp())
                .collect(Collectors.toList());
    }

    public MethodSignature findMethodMatch(DatabaseReferenceFile file, String className, IDexMethod eMethod,
            String methodName) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        List<MethodSignature> sigs = getSignaturesForClassname(file, className, true, eMethod);
        sigs = sigs.stream().filter(s -> s.getMname().equals(methodName)).collect(Collectors.toList());
        MethodSignature ms = findMethodName(sigs, prototypes, true, null, false, className, new ArrayList<>(), eMethod);
        if(ms != null) {
            return ms;
        }
        String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
        return findMethodName(sigs, prototypes, false, shorty, true, className, new ArrayList<>(), eMethod);
    }

    public MethodSignature findMethodMatch(DatabaseReferenceFile file, String classPath,
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

    public MethodSignature findMethodMatch(DatabaseReferenceFile file, String mhash_tight, String prototypes,
            String shorty, String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod,
            boolean allowEmptyMName) {
        MethodSignature strArray = null;
        List<MethodSignature> sigs = ref.getSignatureLines(file, mhash_tight, true);
        if(sigs != null) {
            strArray = findMethodName(sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
        }
        if(strArray == null || (!allowEmptyMName && strArray.getMname().isEmpty())) {
            String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
            sigs = ref.getSignatureLines(file, mhash_loose, false);
            if(sigs != null) {
                strArray = findMethodName(sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
            }
        }
        return strArray;
    }

    public MethodSignature findMethodName(List<MethodSignature> sigs, String classPath,
            Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
        return findMethodName(sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
    }

    public MethodSignature findMethodName(List<MethodSignature> sigs, String proto, String shorty,
            String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        MethodSignature sig = findMethodName(sigs, proto, true, shorty, false, classPath, alreadyProcessedMethods,
                eMethod);
        if(sig != null) {
            return sig;
        }
        if(!firstRound && !firstPass) {
            return findMethodName(sigs, proto, false, shorty, true, classPath, alreadyProcessedMethods, eMethod);
        }
        return null;
    }

    private static List<MethodSignature> findMethodNames(Map<Integer, String> matchedClasses,
            List<MethodSignature> sigs, String prototypes, boolean checkPrototypes, String shorty, boolean checkShorty,
            String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        List<MethodSignature> results = new ArrayList<>();
        for(MethodSignature strArray: sigs) {
            if(!strArray.getCname().equals(classPath)) {
                continue;
            }
            if(!isCompatibleSignature(eMethod, prototypes, checkPrototypes, shorty, checkShorty, strArray)) {
                continue;
            }
            if(isAlreadyProcessed(strArray, alreadyProcessedMethods, checkPrototypes, checkShorty)) {
                continue;
            }
            if(!checkPrototypes && !isCompatiblePrototypeSignature(matchedClasses, eMethod, prototypes, strArray)) {
                continue;
            }
            results.add(strArray);
        }
        return results;
    }

    private static boolean isAlreadyProcessed(MethodSignature strArray,
            Collection<MethodSignature> alreadyProcessedMethods,
            boolean checkPrototypes, boolean checkShorty) {
        for(MethodSignature alreadyProcessed: alreadyProcessedMethods) {
            if(alreadyProcessed.getMname().equals(strArray.getMname())) {
                if((checkPrototypes && alreadyProcessed.getPrototype().equals(strArray.getPrototype()))
                        || checkShorty && alreadyProcessed.getShorty().equals(strArray.getShorty())) {
                    // method has already a match
                    return true;
                }
            }
        }
        return false;
    }

    private MethodSignature findMethodName(List<MethodSignature> sigs, String prototypes, boolean checkPrototypes,
            String shorty, boolean checkShorty, String classPath, Collection<MethodSignature> alreadyProcessedMethods,
            IDexMethod eMethod) {
        List<MethodSignature> results = findMethodNames(dbMatcher.getMatchedClasses(), sigs, prototypes,
                checkPrototypes, shorty, checkShorty, classPath, alreadyProcessedMethods, eMethod);
        if(results.size() == 1) {
            return results.get(0);
        }
        else if(results.size() > 1) {
            filterList(eMethod, prototypes, results);
            if(results.size() == 1) {
                return results.get(0);
            }
            if(!firstRound && !firstPass && checkPrototypes && safe) {
                // kind of last resort when no signature match.
                // in addition, this happens quite often when implementing/extending public api
                // it allows other methods with same signature to be distinguished in some cases
                String methodName = eMethod.getName(true);
                List<MethodSignature> sameNames = results.stream().filter(m -> m.getMname().equals(methodName))
                        .collect(Collectors.toList());
                if(!sameNames.isEmpty()) {
                    if(sameNames.size() == 1) {
                        return sameNames.get(0);
                    }
                    results = sameNames;
                }
            }
            return MatchingSearch.mergeSignature(results);
        }
        return null;
    }

    private static boolean isCompatibleSignature(IDexMethod eMethod, String prototypes, boolean checkPrototypes,
            String shorty, boolean checkShorty, MethodSignature strArray) {
        if(checkPrototypes && !strArray.getPrototype().equals(prototypes)) {
            return false;
        }
        if(checkShorty && !strArray.getShorty().equals(shorty)) {
            return false;
        }
        // init/clinit can not be changed, but is a good indicator for matching
        String methodName = eMethod.getName(true);
        if(checkPrototypes) {
            return DexUtilLocal.isMethodCompatibleWithSignatures(methodName, prototypes, strArray.getMname(),
                    strArray.getPrototype());
        }
        return DexUtilLocal.isMethodCompatible(methodName, strArray.getMname());
    }

    private static boolean isCompatiblePrototypeSignature(Map<Integer, String> matchedClasses, IDexMethod eMethod,
            String prototypes, MethodSignature strArray) {
        String returnVal1 = prototypes.substring(prototypes.indexOf(")") + 1);
        String originalReturnVal = strArray.getPrototype().substring(strArray.getPrototype().indexOf(")") + 1);
        if(!DexUtilLocal.isCompatibleClasses(returnVal1, originalReturnVal)) {
            return false;
        }
        String params1 = DexUtilLocal.extractParamsFromSignature(prototypes);
        String originalParams = DexUtilLocal.extractParamsFromSignature(strArray.getPrototype());
        List<String> paramList = DexUtilLocal.parseSignatureParameters(params1);
        List<String> originalParamList = DexUtilLocal.parseSignatureParameters(originalParams);
        for(int i = 0; i < paramList.size(); i++) {
            String paramI = paramList.get(i);
            String originalParamI = originalParamList.get(i);
            if(paramI.equals(originalParamI)) {
                continue;
            }
            if(matchedClasses.containsValue(paramI)) {
                // not equals, already renamed => either wrong renaming (should not happen often) or not valid candidate
                return false;
            }
            if(!DexUtilLocal.isCompatibleClasses(paramI, originalParamI)) {
                return false;
            }
        }
        return true;
    }

    private void filterList(IDexMethod eMethod, String prototypes, List<MethodSignature> results) {
        for(IAndrosigModule module: modules) {
            Set<MethodSignature> filtered = module.filterList(dex, eMethod, results);
            if(filtered != null && !filtered.isEmpty()) {
                results.clear();
                results.addAll(filtered);
                if(results.size() == 1) {
                    return;
                }
            }
        }
    }

    private static MethodSignature mergeSignature(List<MethodSignature> results) {
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
            String[] vArray = value.getVersions();
            if(vArray != null) {
                for(String version: vArray) {
                    versions.add(version);
                }
            }
        }
        return new MethodSignature(MethodSignature.getClassname(result), MethodSignature.getMethodName(result),
                MethodSignature.getShorty(result), MethodSignature.getPrototype(result), Strings.join(";", versions));
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
