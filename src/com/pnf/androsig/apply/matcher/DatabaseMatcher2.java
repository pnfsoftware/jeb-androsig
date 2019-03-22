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
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.model.SignatureFile;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.IInstruction;
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

    private Map<Integer, String> matchedClassesFile = new HashMap<>();
    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new HashMap<>();
    private Map<Integer, MethodSignature> matchedSigMethods = new HashMap<>();

    private ContextMatches contextMatches = new ContextMatches();

    private Map<Integer, Map<Integer, Integer>> apkCallerLists = null;

    // **** Rebuild structure ****
    // Check duplicate classes (if two or more classes match to the same library class, we need to avoid rename these classes)
    private Map<String, ArrayList<Integer>> dupClasses = new HashMap<>();
    // Check duplicate methods (same as dupClass)
    private Map<Integer, ArrayList<Integer>> dupMethods = new HashMap<>();

    /** Used files -> list of versions match (with occurences) */
    private Map<String, Map<String, Integer>> usedSigFiles = new HashMap<>();

    private Map<Integer, Double> instruCount = new HashMap<>();;

    public DatabaseMatcher2(DatabaseMatcherParameters params, DatabaseReference ref) {
        this.params = params;
        this.ref = ref;
    }

    @Override
    public void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }

        // Fully deterministic: select the best file or nothing: let populate usedSigFiles
        boolean processAll = true;
        for(IDexClass eClass: classes) {
            if(matchedClasses.containsKey(eClass.getIndex())) {
                continue;
            }
            // Get all candidates
            InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, true);
            if(innerMatch != null) {
                storeFinalCandidate(unit, eClass, innerMatch, firstRound);
                processAll = false;
            }
        }

        if(!firstRound && processAll) {
            // more open: now allow to select one file amongst all matching
            for(IDexClass eClass: classes) {
                if(matchedClasses.containsKey(eClass.getIndex())) {
                    continue;
                }
                // Get all candidates
                InnerMatch innerMatch = getClass(unit, eClass, dexHashCodeList, firstRound, false);
                if(innerMatch != null) {
                    storeFinalCandidate(unit, eClass, innerMatch, firstRound);
                }
            }
        }

        // expand: 
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
            //if(!contextMatches.isValid(entry.getValue())) { // TODO
            //    continue;
            //}
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

    private InnerMatch getClass(IDexUnit dex, IDexClass eClass, DexHashcodeList dexHashCodeList, boolean firstRound,
            boolean unique) {
        List<? extends IDexMethod> methods = eClass.getMethods();
        Map<String, Map<String, InnerMatch>> fileCandidates = new HashMap<>(); // file -> (classname->count)
        String originalSignature = eClass.getSignature(true);
        if(originalSignature.contains("$")) {
            String parentSignature = originalSignature.substring(0, originalSignature.lastIndexOf("$")) + ";";
            IDexClass parentClass = dex.getClass(parentSignature);
            String name = matchedClasses.get(parentClass.getIndex());
            if(name != null) {
                // parent class mapping found: what are the inner class defined for?
                String file = matchedClassesFile.get(parentClass.getIndex());
                if(file != null) {
                    SignatureFile sigs = ref.getSignatureFile(file);
                    String innerClass = name.substring(0, name.length() - 1) + "$";
                    List<MethodSignature> compatibleSignatures = new ArrayList<>();
                    for(Entry<String, List<MethodSignature>> entry: sigs.getAllTightSignatures().entrySet()) {
                        for(MethodSignature sig: entry.getValue()) {
                            if(sig.getCname().startsWith(innerClass)) {
                                compatibleSignatures.add(sig);
                            }
                        }
                    }

                    // is there only one class that can match?
                    String cname = mergeSignature(compatibleSignatures).getCname();
                    if(Strings.isBlank(cname)) {
                        //  maybe other inner classes are already matched? Remove them
                        Set<String> innerClasses = compatibleSignatures.stream().map(s -> s.getCname()).collect(Collectors.toSet());
                        for (String inner : innerClasses) {
                            IDexClass innerCl = dex.getClass(inner);
                            if(innerCl != null && matchedClasses.containsKey(innerCl.getIndex())) {
                                compatibleSignatures = compatibleSignatures.stream()
                                        .filter(s -> !s.getCname().equals(inner)).collect(Collectors.toList());
                           }
                        }
                        cname = mergeSignature(compatibleSignatures).getCname();
                    }
                    if(Strings.isBlank(cname)) {
                        if(methods == null || methods.size() == 0) {
                            return null;
                        }
                        fileCandidates = new HashMap<>(); // file -> (classname->count)
                        for(IDexMethod eMethod: methods) {
                            if(!eMethod.isInternal() || matchedMethods.containsKey(eMethod.getIndex())) {
                                continue;
                            }
                            String mhash_tight = dexHashCodeList.getTightHashcode(eMethod);
                            if(mhash_tight == null) {
                                continue;
                            }
                            List<MethodSignature> sigLine = ref.getSignatureLines(file, mhash_tight, true);
                            if(sigLine == null) {
                                continue;
                            }
                            sigLine = sigLine.stream().filter(s -> s.getCname().startsWith(innerClass))
                                    .collect(Collectors.toList());
                            if(sigLine.isEmpty()) {
                                continue;
                            }
                            Map<String, InnerMatch> classes = fileCandidates.get(file);
                            if(classes == null) {
                                classes = new HashMap<>();
                                fileCandidates.put(file, classes);
                            }
                            saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file);
                        }
                    }
                    else {

                        contextMatches.saveMatch(originalSignature, cname, name);
                        return null;
                    }
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
                        saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file);
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
                            saveTemporaryCandidate(dex, eMethod, sigLine, firstRound, classes, file);
                        }
                    }
                }
            }
        }

        // retrieve best candidates only
        Integer higherOccurence = 0;
        List<InnerMatch> bestCandidates = new ArrayList<>();
        for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
            higherOccurence = getBestCandidates(bestCandidates, cand.getValue().values(), higherOccurence);
        }
        if(bestCandidates.size() == 0) {
            return null;
        }

        // Find small methods
        for(InnerMatch cand: bestCandidates) {
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
        InnerMatch bestCandidate = null;
        if(bestCandidates.size() == 1) {
            bestCandidate = bestCandidates.get(0);
        }
        else {
            higherOccurence = 0;
            for(Entry<String, Map<String, InnerMatch>> cand: fileCandidates.entrySet()) {
                higherOccurence = getBestCandidates(bestCandidates, cand.getValue().values(), higherOccurence);
            }
            if(bestCandidates.size() == 1) {
                bestCandidate = bestCandidates.get(0);
            }
            else {
                // TODO Test if methods are the same (can happen with different versions of same lib)
                // May be better to update DatabaseReference to load only once duplicated classes

                // Find total number of methods per class and compare with methods.size()
                TreeMap<Integer, Set<InnerMatch>> diffMatch = new TreeMap<>();
                for(InnerMatch cand: bestCandidates) {
                    Map<String, Integer> methodCountPerVersion = new HashMap<>();
                    SignatureFile sig = ref.getSignatureFile(cand.file);
                    Collection<List<MethodSignature>> allTight = sig.getAllTightSignatures().values();
                    for(List<MethodSignature> tights: allTight) {
                        for(MethodSignature tight: tights) {
                            if(tight.getCname().equals(cand.className)) {
                                String[] versions = tight.getVersions();
                                if(versions == null) {
                                    increment(methodCountPerVersion, "all");
                                }
                                else {
                                    for(String v: versions) {
                                        increment(methodCountPerVersion, v);
                                    }
                                }
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
                else if(firstRound || unique) {
                    return null;
                }
                else {
                    // select one
                    for(InnerMatch cand: bestCandidates) {
                        if(usedSigFiles.containsKey(cand.file)) {
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
        matchedClassesFile.put(eClass.getIndex(), bestCandidate.file);
        return bestCandidate;
    }

    private Map<String, Integer> mergeVersions(String file, Collection<MethodSignature> values) {
        Map<String, Integer> versionOccurences = usedSigFiles.get(file);
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

    private void increment(Map<String, Integer> versionOccurences, String key) {
        Integer val = versionOccurences.get(key);
        if(val == null) {
            versionOccurences.put(key, 1);
        }
        else {
            versionOccurences.put(key, val + 1);
        }
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

    private static class InnerMatch {
        String className;
        Map<Integer, MethodSignature> classPathMethod = new HashMap<>();
        String file;
        List<Integer> doNotRenameIndexes = new ArrayList<>();
    }

    private static void saveTemporaryCandidate(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> elts,
            boolean firstRound, Map<String, InnerMatch> classes, String file) {
        IDexPrototype proto = dex.getPrototypes().get(eMethod.getPrototypeIndex());
        String shorty = proto.getShorty();
        String prototype = proto.generate(true);

        // One class has several same sigs
        List<MethodSignature> realCandidates = elts.stream()
                .filter(strArray -> MethodSignature.getShorty(strArray).equals(shorty)
                && MethodSignature.getPrototype(strArray).equals(prototype)).collect(Collectors.toList());
        if(!realCandidates.isEmpty()) {
            MethodSignature strArray = realCandidates.get(0);
            String className = MethodSignature.getClassname(strArray);
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

    private void storeFinalCandidate(IDexUnit unit, IDexClass eClass, InnerMatch innerMatch, boolean firstRound) {
        if(innerMatch.className.contains("$")) {
            // allow renaming only when parent classes are fine, because inner class tend to be the same in some projects
            String originalSignature = eClass.getSignature(true);
            if(!originalSignature.contains("$")) {
                // inner class match a non inner class => dangerous
                matchedClassesFile.remove(eClass.getIndex());
                return;
            }
            String parentSignature = originalSignature.substring(0, originalSignature.lastIndexOf("$")) + ";";
            String parentMatchSignature = innerMatch.className.substring(0, innerMatch.className.lastIndexOf("$"))
                    + ";";
            if(!parentSignature.equals(parentMatchSignature)) {
                // expect parent match: otherwise, wait for parent match
                if(firstRound) {
                    matchedClassesFile.remove(eClass.getIndex());
                    return;
                } else {
                    String oldClass = eClass.getSignature(true);
                    String newClass = innerMatch.className;
                    while(newClass.contains("$") && oldClass.contains("$")) {
                        int lastIndex = newClass.lastIndexOf('$');
                        String newClassName = newClass.substring(newClass.lastIndexOf('$'));
                        if(!oldClass.endsWith(newClassName)) {
                            contextMatches.saveMatch(oldClass, newClass, innerMatch.className);
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
                logger.i("Found match class: %s from file %s", innerMatch.className, innerMatch.file);
                matchedClasses.put(eClass.getIndex(), innerMatch.className);
                usedSigFiles.put(innerMatch.file, mergeVersions(innerMatch.file, innerMatch.classPathMethod.values()));
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
        apkCallerLists = new HashMap<>();
        SignatureHandler.loadAllCallerLists(unit, apkCallerLists);
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
            if(expectedCallers.size() == 0 && calls.size() == 0) {
                continue;
            }
            if(expectedCallers.size() == 0) {
                // TODO wrong MethodSignature? (merged)
                continue;
            }
            if(expectedCallers.size() != calls.size()) {
                // seems a bit dangerous
                continue;
            }
            if(expectedCallers.size() == 1) {
                String expected = expectedCallers.keySet().iterator().next();
                String current = calls.keySet().iterator().next();
                if(expectedCallers.get(expected).intValue() == calls.get(current)) {
                    contextMatches.saveCallerMatching(unit, expected, current);
                }
            }
            // TODO match several
        }
        return new HashMap<>();
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        // maybe more parameter matches for method signatures (where only shorty matched previously)
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            IDexClass eClass = dex.getClass(entry.getKey());
            if(eClass == null) {
                // class not loaded in dex (maybe in another dex)
                continue;
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
                        String f = matchedClassesFile.get(entry.getKey());
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
                                    if(usedSigFiles.containsKey(file)) {
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
                            Collection<List<MethodSignature>> ssigs = ref.getSignatureFile(file).getAllTightSignatures()
                                    .values();
                            List<MethodSignature> sigs = new ArrayList<>();
                            for(List<MethodSignature> s: ssigs) {
                                sigs.addAll(s);
                            }
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
            String classPath,
            Collection<MethodSignature> methods, IDexMethod eMethod) {
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
            return mergeSignature(results);
        }
        return null;
    }

    private MethodSignature mergeSignature(List<MethodSignature> results) {
        String[] result = new String[9];
        for(int i = 0; i < 9; i++) {
            for(MethodSignature ress: results) {
                String[] res = ress.toTokens();
                if(i >= res.length) {
                    continue;
                }
                if(result[i] == null) {
                    result[i] = res[i];
                }
                else if(!result[i].equals(res[i])) {
                    String methodMatch = result[i] + " OR " + res[i];
                    result[i] = ""; // two lines differ here: may loose callers
                    if(i == 1) {
                        logger.debug("%s: There are several methods matching for signature %s: %s", ress.getCname(),
                                ress.getPrototype(), methodMatch);
                    }
                    break;
                }
            }
        }
        return new MethodSignature(MethodSignature.getClassname(result), MethodSignature.getMethodName(result),
                MethodSignature.getShorty(result), MethodSignature.getPrototype(result), result[4], null);
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
            if(usedSigFiles.containsKey(sig.getKey())) {
                sigCount += sig.getValue().getAllSignatureCount();
            }
        }
        return sigCount;
    }

    @Override
    public int getAllUsedSignatureFileCount() {
        return usedSigFiles.size();
    }

    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        Map<String, LibraryInfo> libs = new HashMap<>();
        for(Entry<Integer, String> entry: matchedClasses.entrySet()) {
            String file = matchedClassesFile.get(entry.getKey());
            if(file == null) {
                for(Entry<String, Map<String, Integer>> used: usedSigFiles.entrySet()) {
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
