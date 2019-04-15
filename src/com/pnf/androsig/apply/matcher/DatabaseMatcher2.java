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
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.matcher.MatchingSearch.InnerMatch;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.model.SignatureFile;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexPrototype;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Aims at building the matched classes and signature in a {@link IDexUnit}. No modification is made
 * on {@link IDexUnit}, the purpose of this class is only to find matches. Call
 * {@link #storeMatchedClassesAndMethods(IDexUnit, DexHashcodeList, boolean)} to perform analysis.
 * See {@link #getMatchedClasses()} and {@link #getMatchedMethods()} for results. This matcher
 * expects a class is replaced by a class (no cross changes). <br>
 * Note that contrary to v1 version which picks only one hashcode, this matcher uses a
 * {@link SignatureFile} per file, allowing to have a precise match, but it may consume more memry.
 * 
 * @author Cedric Lucas
 *
 */
class DatabaseMatcher2 implements IDatabaseMatcher, ISignatureMetrics {
    private final ILogger logger = GlobalLog.getLogger(DatabaseMatcher2.class);

    private DatabaseMatcherParameters params;
    private DatabaseReference ref;
    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new HashMap<>();

    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new HashMap<>();
    private Map<Integer, MethodSignature> matchedSigMethods = new HashMap<>();

    private ContextMatches contextMatches = new ContextMatches();

    private FileMatches fileMatches = new FileMatches();

    private Map<Integer, Map<Integer, Integer>> apkCallerLists = null;

    // **** Rebuild structure ****
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();

    private Map<Integer, Double> instruCount = new HashMap<>();;

    public DatabaseMatcher2(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
        contextMatches.setDbMatcher(this);
    }

    @Override
    public void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
        apkCallerLists = new HashMap<>();
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }

        // Fully deterministic: select the best file or nothing: let populate usedSigFiles
        boolean processSecondPass = storeFinalCandidates(unit, classes, dexHashCodeList, firstRound, true);

        fileMatches.stable = true;

        if(!firstRound && processSecondPass) {
            // more open: now allow to select one file amongst all matching
            storeFinalCandidates(unit, classes, dexHashCodeList, firstRound, false);
        }

        // expand: Add classes and methods found by context (method signature, caller)
        for(Entry<String, String> entry: contextMatches.entrySet()) {
            if(!contextMatches.isValid(entry.getValue())) {
                continue;
            }
            IDexClass cl = unit.getClass(entry.getKey());
            if(cl != null) {
                String newName = matchedClasses.get(cl.getIndex());
                if(newName == null) {
                    matchedClasses.put(cl.getIndex(), entry.getValue());
                }
                else if(!newName.equals(entry.getValue())) {
                    logger.warn("Conflict for class, can not determine best name between %s and %s", newName,
                            entry.getValue());
                }
            }
        }
        for(Entry<Integer, String> entry: contextMatches.methodsEntrySet()) {
            if(!contextMatches.isValid(entry.getValue())) {
                continue;
            }
            String newName = matchedMethods.get(entry.getKey());
            if(newName == null) {
                matchedMethods.put(entry.getKey(), entry.getValue());
            }
            else if(!newName.equals(entry.getValue())) {
                logger.warn("Conflict for method, can not determine best name between %s and %s", newName,
                        entry.getValue());
            }
        }

        // remove duplicates
        for(Entry<String, ArrayList<Integer>> eClass: dupClasses.entrySet()) {
            if(eClass.getValue().size() != 1) {
                for(Integer e: eClass.getValue()) {
                    // remove class
                    matchedClasses.remove(e);
                    // remove methods
                    for(Integer eMethod: dupMethods.get(e)) {
                        matchedMethods.remove(eMethod);
                        matchedSigMethods.remove(eMethod);
                    }
                }
            }
        }
        // GC
        dupClasses.clear();
        dupMethods.clear();
    }

    private boolean storeFinalCandidates(IDexUnit unit, List<? extends IDexClass> classes,
            DexHashcodeList dexHashCodeList, boolean firstRound, boolean firstPass) {
        boolean found = false;
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, firstPass);
            if(innerMatch != null) {
                storeFinalCandidate(unit, eClass, innerMatch, firstRound);
                found = true;
            }
        }
        return found;
    }

    private InnerMatch getClass(IDexUnit dex, IDexClass eClass, DexHashcodeList dexHashCodeList, boolean firstRound,
            boolean unique) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        MatchingSearch fileCandidates = new MatchingSearch(dex, dexHashCodeList, ref, params, fileMatches, firstRound);
        String originalSignature = eClass.getSignature(true);
        int innerLevel = DexUtilLocal.getInnerClassLevel(originalSignature);
        if(DexUtilLocal.isInnerClass(originalSignature)) {
            IDexClass parentClass = DexUtilLocal.getParentClass(dex, originalSignature);
            String name = matchedClasses.get(parentClass.getIndex());
            if(name != null) {
                // parent class mapping found: what are the inner class defined for?
                String file = fileMatches.getFileFromClass(parentClass);
                if(file != null) {
                    SignatureFile sigs = ref.getSignatureFile(file);
                    String innerClass = name.substring(0, name.length() - 1) + "$";
                    List<MethodSignature> compatibleSignatures = sigs.getSignaturesForClassname(innerClass);

                    // is there only one class that can match?
                    List<MethodSignature> candidates = MatchingSearch.mergeSignaturesPerClass(compatibleSignatures);
                    Set<String> versions = FileMatches.getVersions(parentClass, matchedSigMethods);
                    candidates = filterVersions(candidates, versions);
                    candidates = candidates.stream().filter(inner -> !hasClassMatch(dex, inner))
                            .collect(Collectors.toList());
                    if(candidates.size() == 1) {
                        contextMatches.saveClassMatch(originalSignature, candidates.get(0).getCname(), name);
                        return null;
                    }

                    if(methods == null || methods.size() == 0) {
                        return null;
                    }

                    fileCandidates.processInnerClass(file, matchedMethods, methods, innerClass, innerLevel);
                }
                else {
                    //System.out.println("No reference file for " + parentSignature);
                }
            }
        }
        if(methods == null || methods.size() == 0) {
            return null;
        }

        // First round: attempt to match class in its globality
        // Look for candidate files
        if(fileCandidates.isEmpty()) {
            fileCandidates.processClass(matchedClasses, methods, innerLevel);
        }

        if(fileCandidates.isEmpty()) {
            return null;
        }

        // here, we clean up the methods which don't belong to same version
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            for(InnerMatch cand: entry.getValue().values()) {
                cand.validateVersions();
            }
        }

        // Find small methods
        for(Entry<String, Map<String, InnerMatch>> entry: fileCandidates.entrySet()) {
            for(InnerMatch cand: entry.getValue().values()) {
                for(IDexMethod eMethod: methods) {
                    MethodSignature strArray = cand.classPathMethod.get(eMethod.getIndex());
                    if(strArray != null) {
                        continue;
                    }
                    IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                    String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                    if(mhash_tight == null) {
                        continue;
                    }

                    List<MethodSignature> sigs = ref.getSignatureLines(cand.file, mhash_tight, true);
                    if(sigs != null) {
                        strArray = findMethodName(dex, sigs, prototypes, shorty, cand.className,
                                cand.classPathMethod.values(), eMethod);
                    }
                    if(strArray == null) {
                        String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                        sigs = ref.getSignatureLines(cand.file, mhash_loose, false);
                        if(sigs != null) {
                            strArray = findMethodName(dex, sigs, prototypes, shorty, cand.className,
                                    cand.classPathMethod.values(), eMethod);
                        }
                    }
                    if(strArray != null) {
                        cand.classPathMethod.put(eMethod.getIndex(), strArray);
                    }
                }
            }
        }

        Integer higherOccurence = 0;
        List<InnerMatch> bestCandidates = new ArrayList<>();
        for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
            higherOccurence = getBestCandidates(bestCandidates, cand.getValue().values(), higherOccurence);
        }

        InnerMatch bestCandidate = null;
        if (bestCandidates.isEmpty())  {
            return null;
        }
        else if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            // Find total number of methods per class and compare with methods.size()
            TreeMap<Integer, Set<InnerMatch>> diffMatch = new TreeMap<>();
            for(InnerMatch cand: bestCandidates) {
                Map<String, Integer> methodCountPerVersion = new HashMap<>();
                SignatureFile sig = ref.getSignatureFile(cand.file);
                List<MethodSignature> allTight = sig.getSignaturesForClassname(cand.className);
                for(MethodSignature tight: allTight) {
                    String[] versions = tight.getVersions();
                    if(versions == null) {
                        FileMatches.increment(methodCountPerVersion, "all");
                    }
                    else {
                        for(String v: versions) {
                            FileMatches.increment(methodCountPerVersion, v);
                        }
                    }
                }
                for(Integer methodCount: methodCountPerVersion.values()) {
                    int diff = Math.abs(methods.size() - methodCount);
                    Set<InnerMatch> newBestCandidates = diffMatch.get(diff);
                    if(newBestCandidates == null) {
                        newBestCandidates = new HashSet<>();
                        diffMatch.put(diff, newBestCandidates);
                    }
                    newBestCandidates.add(cand);
                }
            }
            bestCandidates = new ArrayList<>(diffMatch.get(diffMatch.firstKey()));

            if(bestCandidates.size() == 1) {
                bestCandidate = bestCandidates.get(0);
            }
            else {
                if (!firstRound) {
                    String className = null;
                    for (InnerMatch cand : bestCandidates) {
                        if (className == null) {
                            className = cand.className;
                        } else if (!className.equals(cand.className)) {
                            className = null;
                            break;
                        }
                    }
                    if(className != null) {
                        // same classname (can happen with different versions of same lib)
                        String bestFile = fileMatches.getMatchedClassFile(eClass, className, ref);
                        if(bestFile != null) {
                            for(InnerMatch cand: bestCandidates) {
                                if(cand.file.equals(bestFile)) {
                                    return cand;
                                }
                            }
                        }
                    }
                }
                if(firstRound || unique) {
                    return null;
                }
                else {
                    // select one
                    for(InnerMatch cand: bestCandidates) {
                        // Several InnerMatch with same level
                        if(fileMatches.usedSigFiles.containsKey(cand.file)) {
                            // consider that same lib is used elsewhere == best chance
                            bestCandidate = cand;
                            break;
                        }
                    }

                    if(bestCandidate == null) {
                        bestCandidate = bestCandidates.get(0);
                    }
                }
            }
        }
        fileMatches.addMatchedClassFiles(eClass, bestCandidate.file);
        return bestCandidate;
    }

    private boolean hasClassMatch(IDexUnit dex, MethodSignature inner) {
        IDexClass innerCl = dex.getClass(inner.getCname());
        return innerCl != null && matchedClasses.containsKey(innerCl.getIndex());
    }

    private List<MethodSignature> filterVersions(List<MethodSignature> candidates, Set<String> versions) {
        if(versions == null) {
            return candidates;
        }
        List<MethodSignature> newCandidates = new ArrayList<>();
        for(MethodSignature cand: candidates) {
            for(String v: versions) {
                if(Arrays.asList(cand.getVersions()).contains(v)) {
                    newCandidates.add(cand);
                    break;
                }
            }
        }
        return newCandidates;
    }

    private static Integer getBestCandidates(List<InnerMatch> bestCandidates, Collection<InnerMatch> candidates,
            Integer higherOccurence) {
        for(InnerMatch candClass: candidates) {
            if(candClass.classPathMethod.size() > higherOccurence) {
                higherOccurence = candClass.classPathMethod.size();
                bestCandidates.clear();
                bestCandidates.add(candClass);
            }
            else if(candClass.classPathMethod.size() == higherOccurence) {
                bestCandidates.add(candClass);
            }
        }
        return higherOccurence;
    }

    private void storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound) {
        if(innerMatch.className.contains("$")) {
            // allow renaming only when parent classes are fine, because inner class tend to be the same in some projects
            String originalSignature = eClass.getSignature(true);
            if(!originalSignature.contains("$")) {
                // inner class match a non inner class => dangerous
                fileMatches.removeClassFiles(eClass);
                return;
            }
            String parentSignature = originalSignature.substring(0, originalSignature.lastIndexOf("$")) + ";";
            String parentMatchSignature = innerMatch.className.substring(0, innerMatch.className.lastIndexOf("$"))
                    + ";";
            if(!parentSignature.equals(parentMatchSignature)) {
                // expect parent match: otherwise, wait for parent match
                if(firstRound) {
                    fileMatches.removeClassFiles(eClass);
                    return;
                } else {
                    String oldClass = eClass.getSignature(true);
                    String newClass = innerMatch.className;
                    // Preprocess: if new class is already renamed, there is no reason to move another one
                    String oldParentClass = oldClass;
                    String newParentClass = newClass;
                    while(newParentClass.contains("$") && oldParentClass.contains("$")) {
                        oldParentClass = oldParentClass.substring(0, oldParentClass.lastIndexOf("$")) + ";";
                        newParentClass = newParentClass.substring(0, newParentClass.lastIndexOf("$")) + ";";
                        int oldClassId = unit.getClass(oldParentClass).getIndex();
                        IDexClass newParentClassObj = unit.getClass(newParentClass);
                        String oldParentMatch = matchedClasses.get(oldClassId);
                        if(oldParentMatch != null) {
                            // parent class has already a match: must be the same
                            if(!oldParentMatch.equals(newParentClass)) {
                                fileMatches.removeClassFiles(eClass);
                                return;
                            }
                        }
                        else if(newParentClassObj != null && matchedClasses.get(newParentClassObj.getIndex()) != null) {
                            // destination class is being/has been renamed but does not match the original class
                            fileMatches.removeClassFiles(eClass);
                            return;
                        }
                    }
                    while(newClass.contains("$") && oldClass.contains("$")) {
                        int lastIndex = newClass.lastIndexOf('$');
                        String newClassName = newClass.substring(newClass.lastIndexOf('$'));
                        if(!oldClass.endsWith(newClassName)) {
                            contextMatches.saveClassMatch(oldClass, newClass, innerMatch.className);
                        }
                        oldClass = oldClass.substring(0, oldClass.lastIndexOf("$")) + ";";
                        newClass = newClass.substring(0, lastIndex) + ";";
                    }
                }
            }
        }
        // Store methods
        ArrayList<Integer> temp1 = new ArrayList<>();
        if(innerMatch.classPathMethod == null || innerMatch.classPathMethod.size() == 0) {
            return;
        }
        for(Entry<Integer, MethodSignature> methodName_method: innerMatch.classPathMethod.entrySet()) {
            temp1.add(methodName_method.getKey());
            String methodName = MethodSignature.getMethodName(methodName_method.getValue());
            if(!Strings.isBlank(methodName) && !innerMatch.doNotRenameIndexes.contains(methodName_method.getKey())) {
                matchedMethods.put(methodName_method.getKey(), methodName);
                matchedSigMethods.put(methodName_method.getKey(), methodName_method.getValue());
            } // else several method name match, need more context
        }

        if(temp1.size() != 0) {
            if(f(unit, eClass, temp1)) {
                boolean res = fileMatches.addVersions(innerMatch.file, innerMatch.classPathMethod.values());
                if(!res) {
                    return;
                }
                logger.i("Found match class: %s from file %s", innerMatch.className, innerMatch.file);
                matchedClasses.put(eClass.getIndex(), innerMatch.className);
                ArrayList<Integer> tempArrayList = dupClasses.get(innerMatch.className);
                if(tempArrayList != null) {
                    tempArrayList.add(eClass.getIndex());
                    dupClasses.put(innerMatch.className, tempArrayList);
                }
                else {
                    ArrayList<Integer> temp2 = new ArrayList<>();
                    temp2.add(eClass.getIndex());
                    dupClasses.put(innerMatch.className, temp2);
                }
                dupMethods.put(eClass.getIndex(), temp1);

                // postprocess: reinject class
                for(Entry<Integer, MethodSignature> methodName_method: innerMatch.classPathMethod.entrySet()) {
                    IDexMethod m = unit.getMethod(methodName_method.getKey());
                    IDexPrototype proto = unit.getPrototypes().get(m.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    MethodSignature strArray = methodName_method.getValue();
                    if(prototypes.equals(MethodSignature.getPrototype(strArray))) {
                        continue;
                    }
                    contextMatches.saveParamMatching(prototypes, MethodSignature.getPrototype(strArray),
                            innerMatch.className, MethodSignature.getMethodName(strArray));
                }
            }
            else {
                for(int e: temp1) {
                    matchedMethods.remove(e);
                    matchedSigMethods.remove(e);
                }
            }
        }
    }

    private boolean f(IDexUnit unit, IDexClass eClass, List<Integer> matchedMethods) {
        double totalInstrus = 0;
        double matchedInstrus = 0;

        Double c = instruCount.get(eClass.getIndex());
        if(c != null) {
            totalInstrus = c;
            for(int e: matchedMethods) {
                matchedInstrus += unit.getMethod(e).getInstructions().size();
            }
        }
        else {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                return false;
            }
            if(methods.size() == 1) {
                // possible false positive: same constructor/super constructor only
                String name = methods.get(0).getName(true);
                if(name.equals("<init>") || name.equals("<clinit>")) {
                    return matchedInstrus > 20; // artificial metrics
                }
            }
            for(IDexMethod m: methods) {
                if(!m.isInternal()) {
                    continue;
                }

                IDexMethodData md = m.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    continue;
                }
                int count = ci.getInstructions().size();
                if(matchedMethods.contains(m.getIndex())) {
                    matchedInstrus += count;
                }
                totalInstrus += count;
                instruCount.put(eClass.getIndex(), totalInstrus);
            }
        }

        if(matchedInstrus / totalInstrus <= params.matchedInstusPercentageBar) {
            return false;
        }
        return true;
    }

    @Override
    public Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        if(apkCallerLists.isEmpty()) {
            SignatureHandler.loadAllCallerLists(unit, apkCallerLists);
        }
        for(Entry<Integer, MethodSignature> match: matchedSigMethods.entrySet()) {
            Map<Integer, Integer> callers = apkCallerLists.get(match.getKey());
            Map<String, Integer> calls = new HashMap<>();
            if(callers != null) {
                for(Entry<Integer, Integer> caller: callers.entrySet()) {
                    IDexMethod m = unit.getMethod(caller.getKey());
                    Integer count = caller.getValue();
                    calls.put(m.getSignature(true), count);
                }
            }
            Map<String, Integer> expectedCallers = match.getValue().getTargetCaller();
            if(expectedCallers.isEmpty() && calls.isEmpty()) {
                continue;
            }
            if(expectedCallers.isEmpty()) {
                expectedCallers = getBestCallers(unit, match.getValue());
                if(expectedCallers == null || expectedCallers.isEmpty()) {
                    continue;
                }
            }
            if(expectedCallers.size() == 1 && calls.size() == 1) {
                String expected = expectedCallers.keySet().iterator().next();
                String current = calls.keySet().iterator().next();
                if(expectedCallers.get(expected).intValue() == calls.get(current)) {
                    contextMatches.saveCallerMatching(unit, expected, current);
                }
            }
            else {
                // look for partial matches
                contextMatches.saveCallerMatchings(unit, expectedCallers, calls);
            }
        }
        return new HashMap<>();
    }

    private Map<String, Integer> getBestCallers(IDexUnit unit, MethodSignature value) {
        // wrong MethodSignature? (merged): retrieve the best caller
        IDexClass cl = unit.getClass(value.getCname());
        if(cl == null) {
            return null;
        }
        String f = fileMatches.getMatchedClassFile(cl, value.getCname(), ref);
        if(f != null) {
            SignatureFile file = ref.getSignatureFile(f);
            List<MethodSignature> candidates = new ArrayList<>();
            List<MethodSignature> compatibleSignatures = file.getSignaturesForClassname(value.getCname());
            for(MethodSignature sig: compatibleSignatures) {
                if(sig.getMname().equals(value.getMname()) && sig.getPrototype().equals(value.getPrototype())
                        && !Strings.isBlank(sig.getCaller())) {
                    candidates.add(sig);
                }
            }
            if(candidates.isEmpty()) {
                // no caller in base list
                return null;
            }
            if(candidates.size() == 1) {
                return candidates.get(0).getTargetCaller();
            }
            candidates = fileMatches.filterMatchingSignatures(f, candidates);
            Map<String, Integer> targetCaller = null;
            for(MethodSignature sig: candidates) {
                if(targetCaller == null) {
                    targetCaller = sig.getTargetCaller();
                }
                else {
                    Map<String, Integer> concurrentTargetCaller = sig.getTargetCaller();
                    if(!targetCaller.equals(concurrentTargetCaller)) {
                        targetCaller = null;  // wait for better one
                        break;
                    }
                }
            }
            return targetCaller;
        }
        return null;
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        if(apkCallerLists.isEmpty()) {
            SignatureHandler.loadAllCallerLists(dex, apkCallerLists);
        }
        // maybe more parameter matches for method signatures (where only shorty matched previously)
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                // class not loaded in dex (maybe in another dex)
                continue;
            }
            String f = fileMatches.getFileFromClass(eClass);
            if(f == null) {
                // update matchedClassesFile
                fileMatches.getMatchedClassFile(eClass, entry.getValue(), ref);
            }
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                // empty class
                continue;
            }
            String className = eClass.getSignature(true);
            List<MethodSignature> alreadyMatches = new ArrayList<>();
            for(IDexMethod eMethod: methods) {
                String methodName = matchedMethods.get(eMethod.getIndex());
                if(methodName == null) {
                    continue;
                }
                IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                String prototypes = proto.generate(true);
                String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                alreadyMatches.add(new MethodSignature(className, methodName, shorty, prototypes, null, null));
            }

            int matchedMethodsSize = alreadyMatches.size();
            do {
                List<String> files = null;
                matchedMethodsSize = alreadyMatches.size();
                for(IDexMethod eMethod: methods) {
                    if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                        continue;
                    }

                    IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
                    String prototypes = proto.generate(true);
                    String shorty = dex.getStrings().get(proto.getShortyIndex()).getValue();
                    String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                    if(mhash_tight == null) {
                        continue;
                    }

                    if(files == null) {
                        // lazy file init
                        f = fileMatches.getFileFromClassId(entry.getKey());
                        if(f == null) {
                            files = ref.getFilesContainingClass(className);
                            if(files == null) {
                                // external library (not in signature files): no need to check other methods
                                break;
                            }
                            if(files.size() > 1) {
                                // attempt to retrieve only used resources/filter
                                List<String> usedFiles = new ArrayList<>();
                                for(String file: files) {
                                    if(fileMatches.usedSigFiles.containsKey(file)) {
                                        usedFiles.add(file);
                                    }
                                }
                                if(!usedFiles.isEmpty()) {
                                    files = usedFiles;
                                }
                            }
                        }
                        else {
                            files = new ArrayList<>();
                            files.add(f);
                        }
                    }

                    String methodName = "";
                    MethodSignature strArray = null;
                    for(String file: files) {
                        List<MethodSignature> sigs = ref.getSignatureLines(file, mhash_tight, true);
                        if(sigs != null) {
                            strArray = findMethodName(dex, sigs, prototypes, shorty, className, alreadyMatches,
                                    eMethod);
                        }
                        if(strArray == null || MethodSignature.getMethodName(strArray).isEmpty()) {
                            String mhash_loose = dexHashCodeList.getLooseHashcode(eMethod);
                            sigs = ref.getSignatureLines(file, mhash_loose, false);
                            if(sigs != null) {
                                strArray = findMethodName(dex, sigs, prototypes, shorty, className, alreadyMatches,
                                        eMethod);
                            }
                        }
                        if(strArray != null) {
                            String newMethodName = MethodSignature.getMethodName(strArray);
                            if(newMethodName.isEmpty()) {
                                methodName = null;
                                break;
                            }
                            else if(methodName.isEmpty()) {
                                methodName = newMethodName;
                            }
                            else if(!methodName.equals(newMethodName)) {
                                methodName = null;
                                break;
                            }
                        }
                        else {
                            methodName = null;
                            break;
                        }
                    }
                    if(Strings.isBlank(methodName) && !firstRound) {
                        // attempt signature matching only
                        methodName = "";
                        for(String file: files) {
                            List<MethodSignature> sigs = ref.getSignatureFile(file)
                                    .getSignaturesForClassname(className);
                            if(!sigs.isEmpty()) {
                                strArray = findMethodName(dex, sigs, prototypes, shorty, className, alreadyMatches,
                                        eMethod);
                            }
                            if(strArray != null) {
                                String newMethodName = MethodSignature.getMethodName(strArray);
                                if(newMethodName.isEmpty()) {
                                    methodName = null;
                                    break;
                                }
                                else if(methodName.isEmpty()) {
                                    methodName = newMethodName;
                                }
                                else if(!methodName.equals(newMethodName)) {
                                    methodName = null;
                                    break;
                                }
                            }
                            else {
                                methodName = null;
                                break;
                            }
                        }
                    }

                    if(!Strings.isBlank(methodName) && !eMethod.getName(true).equals(methodName)) {
                        matchedMethods.put(eMethod.getIndex(), methodName);
                        matchedSigMethods.put(eMethod.getIndex(), strArray);
                        alreadyMatches.add(strArray);

                        // postprocess: reinject class
                        if(!prototypes.equals(MethodSignature.getPrototype(strArray))) {
                            contextMatches.saveParamMatching(prototypes, MethodSignature.getPrototype(strArray),
                                    className, methodName);
                        }
                    }
                }
            }
            while(matchedMethodsSize != alreadyMatches.size());
        }

        return new HashMap<>();
    }

    private MethodSignature findMethodName(IDexUnit dex, List<MethodSignature> sigs, String proto, String shorty,
            String classPath, Collection<MethodSignature> methods, IDexMethod eMethod) {
        MethodSignature sig = findMethodName(dex, sigs, proto, true, classPath, methods, eMethod);
        if(sig != null) {
            return sig;
        }
        return findMethodName(dex, sigs, shorty, false, classPath, methods, eMethod);
    }

    private MethodSignature findMethodName(IDexUnit dex, List<MethodSignature> sigs, String proto, boolean prototype,
            String classPath, Collection<MethodSignature> methods, IDexMethod eMethod) {
        List<MethodSignature> results = new ArrayList<>();
        proto: for(MethodSignature strArray: sigs) {
            if(!(prototype ? strArray.getPrototype(): strArray.getShorty()).equals(proto)) {
                continue;
            }
            if(!MethodSignature.getClassname(strArray).equals(classPath)) {
                continue;
            }
            // init/clinit can not be changed, but is a good indicator for matching
            String methodName = eMethod.getName(true);
            if(methodName.equals("<init>")) {
                if(!strArray.getMname().equals("<init>")) {
                    continue;
                }
            }
            else if(methodName.equals("<clinit>")) {
                if(!strArray.getMname().equals("<clinit>")) {
                    continue;
                }
            }
            else if(strArray.getMname().equals("<init>") || strArray.getMname().equals("<clinit>")) {
                continue;
            }
            for(MethodSignature alreadyProcessed: methods) {
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

    private void filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results) {
        if(apkCallerLists.isEmpty()) {
            return;
        }
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

    /**
     * Get all matched classes.
     * 
     * @return a Map (key: index of a class. Value: a set of all matched classes(path))
     */
    @Override
    public Map<Integer, String> getMatchedClasses() {
        return matchedClasses;
    }

    /**
     * Get all matched methods.
     * 
     * @return a Map (Key: index of a method. Value: actual name of a method)
     */
    @Override
    public Map<Integer, String> getMatchedMethods() {
        return matchedMethods;
    }

    @Override
    public Map<Integer, Map<Integer, Integer>> getApkCallerLists() {
        return new HashMap<>();
    }

    @Override
    public DatabaseMatcherParameters getParameters() {
        return params;
    }

    @Override
    public ISignatureMetrics getSignatureMetrics() {
        return this;
    }

    @Override
    public int getAllSignatureCount() {
        int sigCount = 0;
        for(Entry<String, SignatureFile> sig: ref.getLoadedSignatureFiles().entrySet()) {
            if(fileMatches.usedSigFiles.containsKey(sig.getKey())) {
                sigCount += sig.getValue().getAllSignatureCount();
            }
        }
        return sigCount;
    }

    @Override
    public int getAllUsedSignatureFileCount() {
        return fileMatches.usedSigFiles.size();
    }

    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        Map<String, LibraryInfo> libs = new HashMap<>();
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            String file = fileMatches.getFileFromClassId(entry.getKey());
            if(file == null) {
                for(Entry<String, Map<String, Integer>> used: fileMatches.usedSigFiles.entrySet()) {
                    SignatureFile fileLibs = ref.getSignatureFile(used.getKey());
                    LibraryInfo res = fileLibs.getAllLibraryInfos().get(entry.getValue());
                    if(res != null) {
                        libs.put(entry.getValue(), res);
                        break;
                    }
                }
            }
            else {
                SignatureFile fileLibs = ref.getSignatureFile(file);
                libs.put(entry.getValue(), fileLibs.getAllLibraryInfos().get(entry.getValue()));
            }
        }
        return libs;
    }

}
