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
        private String className;
        private Map<Integer, MethodSignature> classPathMethod = new HashMap<>();
        private Set<MethodSignature> distinctMethods = new HashSet<>();
        private List<String> files;
        List<Integer> doNotRenameIndexes = new ArrayList<>();
        public boolean oneMatch;
        private List<DatabaseReferenceFile> refFiles = new ArrayList<>();

        public InnerMatch(String className, String file) {
            this.className = className;
            this.files = new ArrayList<>();
            files.add(file);
        }

        public InnerMatch(String className, List<String> files) {
            this.className = className;
            this.files = files;
        }

        public String getCname() {
            return className;
        }

        public List<String> getFiles() {
            return files;
        }

        public List<DatabaseReferenceFile> getRefFiles() {
            return refFiles;
        }

        public DatabaseReferenceFile getFirstRefFile() {
            return refFiles.get(0);
        }

        public Collection<MethodSignature> getUsedMethodSignatures() {
            return classPathMethod.values();
        }

        public Set<Integer> getMatchedMethodIndexes() {
            return classPathMethod.keySet();
        }

        public Set<Entry<Integer, MethodSignature>> entrySet() {
            return classPathMethod.entrySet();
        }

        public boolean containsMethod(Integer key) {
            return classPathMethod.containsKey(key);
        }

        public MethodSignature getMethod(Integer key) {
            return classPathMethod.get(key);
        }

        public int methodsSize() {
            return classPathMethod.size();
        }

        public boolean addMethod(IDexMethod eMethod, MethodSignature ms) {
            Integer key = eMethod.getIndex();
            if(classPathMethod.containsKey(key)) {
                return false;
            }

            // Validate that only one method matches that Method Signature
            Integer oldKey = null;
            MethodSignature toRemove = null;
            distinctLoop: for(MethodSignature m: distinctMethods) {
                if(ms.getMname().isEmpty()) {
                    if(m.getPrototype().equals(ms.getPrototype())) {
                        // unknown name + same prototype (or empty)
                        return false;
                    }
                }
                else {
                    if(ms.getMname().equals(m.getMname()) && ms.getPrototype().equals(m.getPrototype())) {
                        // same method: try to determine good one
                        if(eMethod.getSignature(true).equals(ms.getMname())) {
                            // replace
                            toRemove = m;
                            for(Entry<Integer, MethodSignature> entry: classPathMethod.entrySet()) {
                                if(entry.getValue().getMname().equals(ms.getMname())
                                        && entry.getValue().getPrototype().equals(ms.getPrototype())) {
                                    oldKey = entry.getKey();
                                    break distinctLoop;
                                }
                            }
                        }
                        // keep first one otherwise (only one reference)
                        return false;
                    }
                }
            }
            if(toRemove != null) {
                classPathMethod.remove(oldKey);
                distinctMethods.remove(toRemove);
            }

            if(ms.getMname().isEmpty()) {
                //return false;
            }
            classPathMethod.put(key, ms);
            distinctMethods.add(ms);
            return true;
        }

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
            for(String file: files) {
                DatabaseReferenceFile refFile = new DatabaseReferenceFile(file, null);
                refFiles.add(refFile);
                refFile.mergeVersions(classPathMethod.values());
                if(refFile.hasNoVersion()) {
                    continue;
                }
                List<List<String>> preferedOrderList = refFile.getOrderedVersions();
                if(preferedOrderList == null || preferedOrderList.isEmpty()) {
                    continue; //versionless
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
                    refFile = new DatabaseReferenceFile(files.get(0), null);
                    refFile.mergeVersions(classPathMethod.values());
                }
            }
        }
    }

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

    public MatchingSearch(IDexUnit dex, DexHashcodeList dexHashCodeList,
            DatabaseReference ref, DatabaseMatcherParameters params, FileMatches fileMatches,
            List<IAndrosigModule> modules, boolean firstRound, boolean firstPass, boolean safe) {
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

    public void processInnerClass(DatabaseReferenceFile file, IDexClass eClass, List<? extends IDexMethod> methods,
            String innerClass, int innerLevel, List<MethodSignature> compatibleSignatures) {
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
                    IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = null;//proto.getShorty();

                    sigLine = compatibleSignatures.stream()
                            .filter(s -> isCompatibleSignature(s, SignatureCheck.PROTOTYPE_STRICT, shorty, prototypes,
                                    eMethod))
                            .collect(Collectors.toList());
                    if(!isComplexSignature(prototypes)) {
                        String mname = eMethod.getName(true);
                        sigLine = sigLine.stream()
                                .filter(s -> s.getMname().equals(mname)
                                        && !DexUtilLocal.isObjectInheritedMethod(s.getMname(), s.getPrototype()))
                                .collect(Collectors.toList());
                    }
                }
            }
            if(sigLine == null || sigLine.isEmpty()) {
                continue;
            }
            String mname = fileMatches.getMatchedMethod(eMethod);
            if(mname != null) {
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

    public boolean isComplexSignature(String prototypes) {
        String params1 = DexUtilLocal.extractParamsFromSignature(prototypes);
        List<String> paramList = DexUtilLocal.parseSignatureParameters(params1);
        // do not consider one argument methods
        if(paramList.isEmpty() || (paramList.size() == 1 && paramList.get(0).length() == 1)) {
            return false;
        }
        paramList.add(DexUtilLocal.extractReturnValueFromSignature(prototypes));
        int genericApiParams = 0;
        for(String param: paramList) {
            if(param.length() == 1) {
                continue;
            }
            if(DexUtilLocal.isAndroidPlatformClass(param) || DexUtilLocal.isJavaPlatformClass(param)) {
                genericApiParams++;
            }
            return true;
        }
        return genericApiParams >= params.complexSignatureParams;
    }

    public boolean processClass(IMatcherValidation validation, IDexClass eClass, List<? extends IDexMethod> methods,
            int innerLevel) {
        List<String> validFiles = getValidFiles(validation, eClass, methods);
        return processClass(validation, eClass, methods, innerLevel, validFiles);
    }

    public boolean processClass(IMatcherValidation validation, IDexClass eClass, List<? extends IDexMethod> methods,
            int innerLevel, List<String> validFiles) {
        // quick win: to avoid loading all files, consider first if valid in best case
        // meaning: if all methods really match (without looking at prototypes)
        if(!firstRound && !firstPass && validFiles.size() > 1) {
            // restrict list of available files
            validFiles = new ArrayList<>(
                    CollectionUtil.intersect(validFiles, new ArrayList<>(fileMatches.getSignatureFileUsed())));
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
                candidateFiles = new ArrayList<>(CollectionUtil.intersect(validFiles, candidateFiles));
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
                    // remove already matched classes
                    sigLines = sigLines.stream().filter(s -> !fileMatches.containsMatchedClassValue(s.getCname()))
                            .collect(Collectors.toList());

                    // filter methodName hint
                    String mname = fileMatches.getMatchedMethod(eMethod);
                    if(mname != null) {
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
                        String mname = fileMatches.getMatchedMethod(eMethod);
                        if(mname != null) {
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
        IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<MethodSignature> realCandidates = elts.stream()
                .filter(strArray -> isCompatibleSignature(strArray, SignatureCheck.PROTOTYPE_COMPATIBLE, shorty,
                        prototype, eMethod))
                .collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            List<MethodSignature> strArrays = mergeSignaturesPerClass(realCandidates, eMethod);
            for(MethodSignature strArray: strArrays) {
                String className = strArray.getCname();
                if(DexUtilLocal.getInnerClassLevel(className) != innerLevel) {
                    continue;
                }
                InnerMatch inner = classes.get(className);
                if(inner == null) {
                    inner = new InnerMatch(className, file);
                }
                inner.addMethod(eMethod, strArray);
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
        IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        List<MethodSignature> sigs = getSignaturesForClassname(file, className, true, eMethod);
        sigs = sigs.stream().filter(s -> s.getMname().equals(methodName)).collect(Collectors.toList());
        MethodSignature ms = findMethodName(sigs, SignatureCheck.PROTOTYPE_STRICT, prototypes, null, className,
                new ArrayList<>(), eMethod);
        if(ms != null) {
            return ms;
        }
        String shorty = proto.getShorty();
        return findMethodName(sigs, SignatureCheck.PROTOTYPE_COMPATIBLE, prototypes, shorty, className,
                new ArrayList<>(), eMethod);
    }

    public MethodSignature findMethodMatch(DatabaseReferenceFile file, String classPath,
            Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod, boolean allowEmptyMName) {
        IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        String shorty = proto.getShorty();
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
        IDexPrototype proto = dex.getPrototype(eMethod.getPrototypeIndex());
        String prototypes = proto.generate(true);
        String shorty = proto.getShorty();
        return findMethodName(sigs, prototypes, shorty, classPath, alreadyProcessedMethods, eMethod);
    }

    public MethodSignature findMethodName(List<MethodSignature> sigs, String proto, String shorty,
            String classPath, Collection<MethodSignature> alreadyProcessedMethods, IDexMethod eMethod) {
        MethodSignature sig = findMethodName(sigs, SignatureCheck.PROTOTYPE_STRICT, proto, shorty, classPath,
                alreadyProcessedMethods, eMethod);
        if(sig != null) {
            return sig;
        }
        if(!firstRound && !firstPass) {
            return findMethodName(sigs, SignatureCheck.PROTOTYPE_COMPATIBLE, proto, shorty, classPath,
                    alreadyProcessedMethods, eMethod);
        }
        return null;
    }

    private List<MethodSignature> findMethodNames(List<MethodSignature> sigs, SignatureCheck check,
            String prototypes, String shorty, String classPath, Collection<MethodSignature> alreadyProcessedMethods,
            IDexMethod eMethod) {
        List<MethodSignature> results = new ArrayList<>();
        for(MethodSignature strArray: sigs) {
            if(!strArray.getCname().equals(classPath)) {
                continue;
            }
            if(!isCompatibleSignature(strArray, check, shorty, prototypes, eMethod)) {
                continue;
            }
            if(isAlreadyProcessed(strArray, alreadyProcessedMethods, check == SignatureCheck.PROTOTYPE_STRICT,
                    check != SignatureCheck.PROTOTYPE_STRICT)) {
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

    private MethodSignature findMethodName(List<MethodSignature> sigs, SignatureCheck check, String prototypes,
            String shorty, String classPath, Collection<MethodSignature> alreadyProcessedMethods,
            IDexMethod eMethod) {
        List<MethodSignature> results = findMethodNames(sigs, check, prototypes, shorty,
                classPath, alreadyProcessedMethods, eMethod);
        if(results.size() == 1) {
            return results.get(0);
        }
        else if(results.size() > 1) {
            filterList(eMethod, prototypes, results);
            if(results.size() == 1) {
                return results.get(0);
            }
            return MethodSignature.mergeSignatures(results, true, eMethod);
        }
        return null;
    }

    public static enum SignatureCheck {
        PROTOTYPE_STRICT, PROTOTYPE_COMPATIBLE, SHORTY
    }

    private boolean isCompatibleSignature(MethodSignature strArray, SignatureCheck check, String shorty,
            String prototypes, IDexMethod eMethod) {
        if(!isCompatibleSignature(strArray, check, shorty, prototypes)) {
            return false;
        }

        // init/clinit can not be changed, but is a good indicator for matching
        String methodName = eMethod.getName(true);
        if(check == SignatureCheck.PROTOTYPE_COMPATIBLE || check == SignatureCheck.PROTOTYPE_STRICT) {
            return DexUtilLocal.isMethodCompatibleWithSignatures(methodName, prototypes, strArray.getMname(),
                    strArray.getPrototype());
        }
        return DexUtilLocal.isMethodCompatible(methodName, strArray.getMname());
    }

    private boolean isCompatibleSignature(MethodSignature strArray, SignatureCheck check, String shorty,
            String prototype) {
        switch(check) {
        case PROTOTYPE_STRICT:
            return strArray.getPrototype().equals(prototype);
        case SHORTY:
            return strArray.getShorty().equals(shorty);
        case PROTOTYPE_COMPATIBLE:
            if(strArray.getPrototype().equals(prototype)) {
                return true;
            }
            if(!strArray.getShorty().equals(shorty)) {
                return false;
            }
            return isCompatiblePrototypeSignature(strArray, prototype);
        default:
            break;
        }
        return false;
    }

    private boolean isCompatiblePrototypeSignature(MethodSignature strArray, String prototypes) {
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
            if(fileMatches.containsMatchedClassValue(paramI)) {
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

    static List<MethodSignature> mergeSignaturesPerClass(List<MethodSignature> results, IDexMethod eMethod) {
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
            merged.add(MethodSignature.mergeSignatures(values, true, eMethod));
        }
        return merged;
    }

    public boolean isEmpty() {
        return fileCandidates.isEmpty();
    }

    public Set<Entry<String, Map<String, InnerMatch>>> entrySet() {
        return fileCandidates.entrySet();
    }

    public void filterClassName(String hintName) {
        List<String> toRemove = new ArrayList<>();
        for(Entry<String, Map<String, InnerMatch>> entry: entrySet()) {
            InnerMatch m = entry.getValue().get(hintName);
            if(m == null) {
                toRemove.add(entry.getKey());
            }
            else if(entry.getValue().size() != 1) {
                entry.getValue().clear();
                entry.getValue().put(hintName, m);
            }
        }
        for(String r: toRemove) {
            fileCandidates.remove(r);
        }


        if(fileCandidates.isEmpty()) {
            List<String> files = ref.getFilesContainingClass(hintName);
            if(files == null) {
                // file not in lib
                return;
            }
            for(String f: files) {
                InnerMatch m = new InnerMatch(hintName, f);
                Map<String, InnerMatch> value = new HashMap<>();
                value.put(hintName, m);
                fileCandidates.put(f, value);
            }
        }
    }

}
