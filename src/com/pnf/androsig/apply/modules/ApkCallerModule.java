/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.modules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.matcher.ContextMatches;
import com.pnf.androsig.apply.matcher.DatabaseReferenceFile;
import com.pnf.androsig.apply.matcher.FileMatches;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
public class ApkCallerModule extends AbstractModule {


    private Map<Integer, Map<Integer, Integer>> apkCallerLists = null;

    public ApkCallerModule(ContextMatches contextMatches, FileMatches fileMatches,
            DatabaseReference ref) {
        super(contextMatches, fileMatches, ref);
    }

    @Override
    public void initNewPass(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound) {
        apkCallerLists = new HashMap<>();
    }

    @Override
    public Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        if(apkCallerLists.isEmpty()) {
            SignatureHandler.loadAllCallerLists(unit, apkCallerLists);
        }
        for(Entry<Integer, MethodSignature> match: fileMatches.entrySetMatchedSigMethods()) {
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
                    saveCallerMatching(unit, expected, current);
                }
            }
            else {
                // look for partial matches
                saveCallerMatchings(unit, expectedCallers, calls);
            }
        }
        return new HashMap<>();
    }

    @Override
    public Map<Integer, String> postProcessRenameClasses(IDexUnit dex, DexHashcodeList dexHashCodeList,
            boolean firstRound) {
        if(apkCallerLists.isEmpty()) {
            SignatureHandler.loadAllCallerLists(dex, apkCallerLists);
        }
        return new HashMap<>();
    }

    private Map<String, Integer> getBestCallers(IDexUnit unit, MethodSignature value) {
        // wrong MethodSignature? (merged): retrieve the best caller
        IDexClass cl = unit.getClass(value.getCname());
        if(cl == null) {
            return null;
        }
        DatabaseReferenceFile f = getFileFromClass(unit, cl);
        if(f != null) {
            List<MethodSignature> candidates = new ArrayList<>();
            List<MethodSignature> compatibleSignatures = getSignaturesForClassname(f, value.getCname());
            for(MethodSignature sig: compatibleSignatures) {
                if(sig.getMname().equals(value.getMname()) && sig.getPrototype().equals(value.getPrototype())
                        && sig.hasCaller()) {
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
            Map<String, Integer> targetCaller = null;
            for(MethodSignature sig: candidates) {
                if(targetCaller == null) {
                    targetCaller = sig.getTargetCaller();
                }
                else {
                    Map<String, Integer> concurrentTargetCaller = sig.getTargetCaller();
                    if(!targetCaller.equals(concurrentTargetCaller)) {
                        targetCaller = null; // wait for better one
                        break;
                    }
                }
            }
            return targetCaller;
        }
        return null;
    }

    public void saveCallerMatching(IDexUnit unit, String expected, String current) {
        IDexMethod m = unit.getMethod(current);
        if(m == null) {
            // trying to work on non renamed method. renaming failed or was not processed at this point
            return;
        }
        String[] expectedTokens = expected.split("->|\\(|\\)"); //0: classname, 1: methodname, 2: arguments, 3: return
        String[] currentTokens = current.split("->|\\(|\\)");
        if(expected.equals(current)) {
            saveMethodMatch(m.getIndex(), expectedTokens[1]);
            return;
        }
        List<String> expectedParams = DexUtilLocal.parseSignatureParameters(expectedTokens[2]);
        List<String> currentParams = DexUtilLocal.parseSignatureParameters(currentTokens[2]);
        if(!areParamsSignatureCompatibles(unit, expectedParams, currentParams)
                || !DexUtilLocal.isMethodCompatibleWithParams(expectedTokens[1], expectedTokens[2], currentTokens[1],
                        currentTokens[2])
                || !isSignatureCompatible(unit, expectedTokens[0], currentTokens[0])
                || !isSignatureCompatible(unit, expectedTokens[3], currentTokens[3])) {
            return;
        }
        applyClassMatching(expectedTokens, currentTokens);
        applyMethodMatching(m, expectedTokens[0], expectedTokens[1], expectedParams, currentParams);
    }

    private void applyClassMatching(String[] expectedTokens, String[] currentTokens) {
        saveClassMatch(currentTokens[0], expectedTokens[0], expectedTokens[0], expectedTokens[1]);
        saveClassMatch(currentTokens[3], expectedTokens[3], expectedTokens[0], expectedTokens[1]);
    }

    private void applyMethodMatching(IDexMethod m, String cname, String name, List<String> expectedParams,
            List<String> currentParams) {
        saveMethodMatch(m.getIndex(), name);
        for(int i = 0; i < expectedParams.size(); i++) {
            saveClassMatch(currentParams.get(i), expectedParams.get(i), cname, name);
        }
    }

    public void saveCallerMatchings(IDexUnit unit, Map<String, Integer> expectedCallers,
            Map<String, Integer> currents) {
        Map<String, String[]> currentsSplits = new HashMap<>();
        Map<String, List<String>> currentsParams = new HashMap<>();
        for(String current: currents.keySet()) {
            String[] currentTokens = current.split("->|\\(|\\)"); //0: classname, 1: methodname, 2: arguments, 3: return
            currentsSplits.put(current, currentTokens);
            List<String> currentParams = DexUtilLocal.parseSignatureParameters(currentTokens[2]);
            currentsParams.put(current, currentParams);
        }
        Map<String, String[]> expectedsSplits = new HashMap<>();
        Map<String, List<String>> expectedsParams = new HashMap<>();
        for(String expected: expectedCallers.keySet()) {
            String[] expectedTokens = expected.split("->|\\(|\\)");
            expectedsSplits.put(expected, expectedTokens);
            List<String> expectedParams = DexUtilLocal.parseSignatureParameters(expectedTokens[2]);
            expectedsParams.put(expected, expectedParams);
        }
        Map<String, List<String>> matchings = new HashMap<>();
        Map<String, String> resolved = new HashMap<>();
        for(Entry<String, Integer> expected: expectedCallers.entrySet()) {
            // search candidates
            String[] expectedTokens = expectedsSplits.get(expected.getKey());
            List<String> expectedParams = expectedsParams.get(expected.getKey());
            List<String> candidates = new ArrayList<>();
            for(Entry<String, Integer> current: currents.entrySet()) {
                if(current.getValue().intValue() != expected.getValue()) {
                    continue;
                }
                if(expected.getKey().equals(current.getKey())) {
                    // perfect match found
                    candidates.clear();
                    candidates.add(current.getKey());
                    break;
                }
                List<String> currentParams = currentsParams.get(current.getKey());
                String[] currentTokens = currentsSplits.get(current.getKey());
                if(!areParamsSignatureCompatibles(unit, expectedParams, currentParams)
                        || !DexUtilLocal.isMethodCompatibleWithParams(expectedTokens[1], expectedTokens[2],
                                currentTokens[1], currentTokens[2])
                        || !isSignatureCompatible(unit, expectedTokens[0], currentTokens[0])
                        || !isSignatureCompatible(unit, expectedTokens[3], currentTokens[3])) {
                    continue;
                }
                candidates.add(current.getKey());
            }
            if(candidates.isEmpty()) {
                return;
            }
            if(candidates.size() == 1) {
                resolved.put(expected.getKey(), candidates.get(0));
            }
            else {
                matchings.put(expected.getKey(), candidates);
            }
        }
        // valid if there is at least one valid matching
        // if real case, allow to retrieve callers (no need for perfect validation)
        //if(!validateCallerMatchings(unit, matchings, resolved)) {
        //    return;
        //}
        // apply
        for(Entry<String, String> resol: resolved.entrySet()) {
            String[] expectedTokens = expectedsSplits.get(resol.getKey());
            List<String> expectedParams = expectedsParams.get(resol.getKey());
            List<String> currentParams = currentsParams.get(resol.getValue());
            String[] currentTokens = currentsSplits.get(resol.getValue());
            applyClassMatching(expectedTokens, currentTokens);
            IDexMethod m = unit.getMethod(resol.getValue());
            if(m == null) {
                // TODO cannot retrieve method??
                continue;
            }
            applyMethodMatching(m, expectedTokens[0], expectedTokens[1], expectedParams, currentParams);
        }

        for(Entry<String, List<String>> match: matchings.entrySet()) {
            // can not determinate methods, but can still be classes
            String[] expectedTokens = expectedsSplits.get(match.getKey());
            List<String> expectedParams = expectedsParams.get(match.getKey());
            List<String> mergedParams = new ArrayList<>();
            String[] mergedTokens = new String[expectedTokens.length];
            for(String candidate: match.getValue()) {
                List<String> currentParams = currentsParams.get(candidate);
                String[] currentTokens = currentsSplits.get(candidate);
                if(mergedParams.isEmpty()) {
                    mergedParams.addAll(currentParams);
                    mergedTokens[0] = currentTokens[0];
                    mergedTokens[3] = currentTokens[3];
                }
                else {
                    for(int i = 0; i < mergedParams.size(); i++) {
                        mergedParams.set(i, merge(mergedParams.get(i), currentParams.get(i)));
                    }
                    mergedTokens[0] = merge(mergedTokens[0], currentTokens[0]);
                    mergedTokens[3] = merge(mergedTokens[3], currentTokens[3]);
                }
            }
            // apply if some
            for(int i = 0; i < mergedParams.size(); i++) {
                if(!Strings.isBlank(mergedParams.get(i))) {
                    saveClassMatch(mergedParams.get(i), expectedParams.get(i), expectedTokens[0], expectedTokens[1]);
                }
            }
            if(!Strings.isBlank(mergedTokens[0])) {
                saveClassMatch(mergedTokens[0], expectedTokens[0], expectedTokens[0], expectedTokens[1]);
            }
            if(!Strings.isBlank(mergedTokens[3])) {
                saveClassMatch(mergedTokens[3], expectedTokens[3], expectedTokens[0], expectedTokens[1]);
            }
        }
    }

    private String merge(String string, String string2) {
        if(string == null) {
            return null;
        }
        if(string.equals(string2)) {
            return string;
        }

        int idx1 = string.lastIndexOf("$");
        int idx2 = string2.lastIndexOf("$");
        if(idx1 > 0 && idx2 > 0) {
            // attempt to merge parent class at least
            return merge(string.substring(0, idx1) + ";", string2.substring(0, idx2) + ";");
        }
        return null;
    }

    /*
    private boolean validateCallerMatchings(IDexUnit unit, Map<String, List<String>> matchings,
            Map<String, String> resolved) {
        if(resolved.values().size() != new HashSet<>(resolved.values()).size()) {
            // several point to same matching (at least one is wrong)
            return false;
        }
        if(matchings.size() == 0) {
            // all bound 1 to 1: quick win: no duplicated
            return true;
        }
    
        // try to build a valid combinations: if at least one exists, it is enough to validate resolved list
        Map<String, List<String>> matchingsDup = new HashMap<>(matchings);
        List<String> excluded = new ArrayList<>(resolved.values());
        List<Map<String, String>> resolvedAttempt = performCombinations(matchingsDup, excluded);
        if(resolvedAttempt == null) {
            return false;
        }
        for(Map<String, String> combination: resolvedAttempt) {
            combination.putAll(resolved);
            if(validateCallerMatchings(unit, matchingsDup, combination)) {
                return true;
            }
        }
        return false;
    }
    
    private List<Map<String, String>> performCombinations(Map<String, List<String>> matchingsDup,
            Collection<String> excluded) {
        String key = matchingsDup.keySet().iterator().next();
        List<String> matchs = matchingsDup.remove(key);
    
        List<Map<String, String>> newResolvedAttempt = null;
        if(!matchingsDup.isEmpty()) {
            // shortcut faster if some combinations are invalid
            newResolvedAttempt = performCombinations(matchingsDup, excluded);
            if(newResolvedAttempt == null || newResolvedAttempt.isEmpty()) {
                return null;
            }
        }
    
        List<Map<String, String>> resolvedAttempt = new ArrayList<>();
        for (String match: matchs) {
            if(excluded.contains(match)) {
                continue;
            }
            Map<String, String> bind = new HashMap<>();
            bind.put(key, match);
            resolvedAttempt.add(bind);
        }
        if(resolvedAttempt.isEmpty()) {
            // no matching, in fact
            return null;
        }
    
        if(newResolvedAttempt == null) {
            return resolvedAttempt;
        }
        List<Map<String, String>> finalResolvedAttempt = new ArrayList<>();
        // n! processing by using intersection
        for(Map<String, String> map1: resolvedAttempt) {
            for(Map<String, String> map2: newResolvedAttempt) {
                if(CollectionUtil.intersection(new ArrayList<>(map1.values()), new ArrayList<>(map2.values()))
                        .isEmpty()) {
                    Map<String, String> finalMap = new HashMap<>();
                    finalMap.putAll(map1);
                    finalMap.putAll(map2);
                    finalResolvedAttempt.add(finalMap);
                }
            }
        }
        return finalResolvedAttempt;
    }
    */

    private boolean areParamsSignatureCompatibles(IDexUnit unit, List<String> expectedParams,
            List<String> currentParams) {
        if(expectedParams.size() != currentParams.size()) {
            return false;
        }
        for(int i = 0; i < expectedParams.size(); i++) {
            if(!isSignatureCompatible(unit, expectedParams.get(i), currentParams.get(i))) {
                return false;
            }
        }
        return true;
    }

    private boolean isSignatureCompatible(IDexUnit unit, String expected, String current) {
        if(expected.equals(current)) {
            return true;
        }
        int typeChar = 0;
        while(expected.charAt(typeChar) == '[' && current.charAt(typeChar) == '[') {
            typeChar++;
        }
        if(expected.charAt(typeChar) != current.charAt(typeChar)) {
            return false;
        }
        current = current.substring(typeChar);
        IDexClass cl = unit.getClass(current); // must exist
        expected = expected.substring(typeChar);
        IDexClass clExp = unit.getClass(expected); // may be null (obfuscated)
        if(cl != null) {
            if(clExp != null) {
                return false; // not the same class after naming is stable
            }
            else {
                // specific cases for inner classes:
                int currentIdx = current.indexOf("$");
                int expectedIdx = expected.indexOf("$");
                while(currentIdx > 0 || expectedIdx > 0) {
                    // deepness must match + parent classes
                    if(currentIdx < 0 || expectedIdx < 0) {
                        return false;
                    }
                    String expectedParentName = expected.substring(0, expectedIdx) + ";";
                    String currentParentName = current.substring(0, currentIdx) + ";";
                    if(!expectedParentName.equals(currentParentName)) {
                        // are subclasses compatible
                        IDexClass clParentExp = unit.getClass(expectedParentName);
                        IDexClass clParent = unit.getClass(currentParentName);
                        if(clParentExp != null) {
                            return false; // not the same class after naming is stable
                        }
                        else if(hasMatchedClass(clParent.getIndex())) {
                            return false; // renaming already performed (match another class)
                        }
                    }

                    currentIdx = current.indexOf("$", currentIdx + 1);
                    expectedIdx = expected.indexOf("$", expectedIdx + 1);
                }
                // only compatible if no renaming was done (otherwise, expect same type)
                return !hasMatchedClass(cl.getIndex());
            }
        }
        else {
            // class not in current dex: library that can not be renamed: must match
            return false;
        }
    }

    @Override
    public Set<MethodSignature> filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results) {
        // secondly, filter by caller
        if(apkCallerLists.isEmpty()) {
            return null;
        }
        Map<Integer, Integer> callers = apkCallerLists.get(eMethod.getIndex());
        if(callers == null) {
            return null;
        }
        // caller may not be referenced in lib
        Set<MethodSignature> filtered = new HashSet<>();
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
        return filtered;
    }

}
