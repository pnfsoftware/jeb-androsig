/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.base.JavaUtil;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Represent a binding from an old classname to a new classname.
 * 
 * @author Cedric Lucas
 *
 */
public class ContextMatches {
    private final ILogger logger = GlobalLog.getLogger(ContextMatches.class);

    private static final String INVALID_MATCH = "INVALID";

    private Map<String, String> contextMatches = new HashMap<>();

    private Map<Integer, String> methodMatches = new HashMap<>();
    private IDatabaseMatcher dbMatcher;

    public void setDbMatcher(IDatabaseMatcher dbMatcher) {
        this.dbMatcher = dbMatcher;

    }
    public void saveParamMatching(String oldProto, String newProto, String className, String methodName) {
        // extract return type
        String[] tokens1 = oldProto.substring(1).split("\\)");
        if(newProto.isEmpty()) {
            // several candidates: TODO check versions or wait for final matching
            return;
        }
        String[] tokens2 = newProto.substring(1).split("\\)");
        if(tokens1.length != 2 || tokens2.length != 2) {
            return;
        }
        List<String> oldClasses = parseSignatureParameters(tokens1[0]);
        oldClasses.add(tokens1[1]);
        List<String> newClasses = parseSignatureParameters(tokens2[0]);
        newClasses.add(tokens2[1]);
        if(oldClasses.size() != newClasses.size()) {
            // parameter non use removed? too risky
            return;
        }
        for(int i = 0; i < oldClasses.size(); i++) {
            String oldClass = oldClasses.get(i);
            String newClass = newClasses.get(i);
            if(!oldClass.equals(newClass) && oldClass.endsWith(";")) {
                // return value updated
                while(oldClass.charAt(0) == '[') {
                    if(newClass.charAt(0) != '[') {
                        // argument swaps?
                        return;
                    }
                    oldClass = oldClass.substring(1);
                    newClass = newClass.substring(1);
                }
                while(newClass.contains("$") && oldClass.contains("$")) {
                    int lastIndex = newClass.lastIndexOf('$');
                    String newClassName = newClass.substring(newClass.lastIndexOf('$'));
                    if(!oldClass.endsWith(newClassName)) {
                        saveClassMatch(oldClass, newClass, className, methodName);
                    }
                    oldClass = oldClass.substring(0, oldClass.lastIndexOf("$")) + ";";
                    newClass = newClass.substring(0, lastIndex) + ";";
                }
                if(!oldClass.equals(newClass)) {
                    saveClassMatch(oldClass, newClass, className, methodName);
                }
            }
        }
    }

    public void saveClassMatch(String oldClass, String newClass, String innerClass) {
        if(saveClassMatch(oldClass, newClass) == Boolean.TRUE) {
            logger.i("Found match class: %s related to innerClass %s", newClass, innerClass);
        }
    }

    public void saveClassMatchInherit(String oldClass, String newClass, String inherit) {
        if(saveClassMatch(oldClass, newClass) == Boolean.TRUE) {
            logger.i("Found match class: %s related to inherited %s", newClass, inherit);
        }
    }

    public void saveClassMatch(String oldClass, String newClass, String className, String methodName) {
        if(oldClass.charAt(0) == 'L' && newClass.charAt(0) == 'L') {
            if(saveClassMatch(oldClass, newClass) == Boolean.TRUE) {
                logger.info("Found match class: %s by param matching from %s->%s", newClass, className, methodName);
            }
        }
    }

    public void setInvalidClass(String key) {
        contextMatches.put(key, INVALID_MATCH);
    }

    public void setInvalidMethod(Integer key) {
        methodMatches.put(key, INVALID_MATCH);
    }

    private Boolean saveClassMatch(String oldClass, String newClass) {
        String value = contextMatches.get(oldClass);
        if(value != null) {
            if(value.equals(INVALID_MATCH)) {
                return Boolean.FALSE;
            }
            else if(!value.equals(newClass)) {
                logger.error("Conflict: class %s has two candidates %s and new %s", oldClass, value, newClass);
                contextMatches.put(oldClass, INVALID_MATCH);
                return Boolean.FALSE;
            }
            return null;
        }
        if(contextMatches.containsValue(newClass) && !oldClass.equals(newClass)) { // allow old binding to new binding
            String conflictVal = null;
            for(Entry<String, String> c: contextMatches.entrySet()) {
                if(c.getValue().equals(newClass)) {
                    conflictVal = c.getKey();
                    break;
                }
            }
            logger.error("Conflict: candidate %s has two class matching: %s and new %s", newClass, conflictVal,
                    oldClass);
            contextMatches.put(oldClass, INVALID_MATCH);
            contextMatches.put(newClass, INVALID_MATCH);
            return Boolean.FALSE;
        }
        contextMatches.put(oldClass, newClass);
        return Boolean.TRUE;
    }

    private static List<String> parseSignatureParameters(String parameters) {
        List<String> params = new ArrayList<>();
        int i = 0;
        while(i < parameters.length()) {
            int begin = i;
            while(parameters.charAt(i) == '[') {
                i++;
            }
            char type = parameters.charAt(i);
            if(type == 'L') {
                int end = parameters.indexOf(';', i);
                if(end < 0) {
                    // invalid sig
                    return null;
                }
                params.add(parameters.substring(begin, end + 1));
                i = end + 1;
            }
            else if(JavaUtil.letterToPrimitive(type + "") != null) {
                params.add(parameters.substring(begin, i + 1));
                i++;
            }
            else {
                // invalid param
                return null;
            }
        }
        return params;
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
        List<String> expectedParams = parseSignatureParameters(expectedTokens[2]);
        List<String> currentParams = parseSignatureParameters(currentTokens[2]);
        if(!areParamsSignatureCompatibles(unit, expectedParams, currentParams)
                || !isMethodCompatible(unit, expectedTokens[1], currentTokens[1])
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
            List<String> currentParams = parseSignatureParameters(currentTokens[2]);
            currentsParams.put(current, currentParams);
        }
        Map<String, String[]> expectedsSplits = new HashMap<>();
        Map<String, List<String>> expectedsParams = new HashMap<>();
        for(String expected: expectedCallers.keySet()) {
            String[] expectedTokens = expected.split("->|\\(|\\)");
            expectedsSplits.put(expected, expectedTokens);
            List<String> expectedParams = parseSignatureParameters(expectedTokens[2]);
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
                        || !isMethodCompatible(unit, expectedTokens[1], currentTokens[1])
                        || !isSignatureCompatible(unit, expectedTokens[0], currentTokens[0])
                        || !isSignatureCompatible(unit, expectedTokens[3], currentTokens[3])) {
                    continue;
                }
                candidates.add(current.getKey());
            }
            if (candidates.isEmpty()) {
                return;
            }
            if (candidates.size() == 1) {
                resolved.put(expected.getKey(), candidates.get(0));
            } else {
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
    boolean saveMethodMatch(Integer oldMethod, String newMethod) {
        String value = methodMatches.get(oldMethod);
        if(value != null) {
            if(value.equals(INVALID_MATCH)) {
                return false;
            }
            else if(!value.equals(newMethod)) {
                methodMatches.put(oldMethod, INVALID_MATCH);
                return false;
            }
        }
        methodMatches.put(oldMethod, newMethod);
        return true;
    }

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
                        else if(dbMatcher.getMatchedClasses().get(clParent.getIndex()) != null) {
                            return false; // renaming already performed (match another class)
                        }
                    }

                    currentIdx = current.indexOf("$", currentIdx + 1);
                    expectedIdx = expected.indexOf("$", expectedIdx + 1);
                }
                // only compatible if no renaming was done (otherwise, expect same type)
                return dbMatcher.getMatchedClasses().get(cl.getIndex()) == null;
            }
        }
        else {
            // class not in current dex: library that can not be renamed: must match
            return false;
        }
    }

    private boolean isMethodCompatible(IDexUnit unit, String expected, String current) {
        if("<init>".equals(expected) != "<init>".equals(current)
                || "<clinit>".equals(expected) != "<clinit>".equals(current)) {
            return false;
        }
        return true;
    }
    public Set<Entry<String, String>> entrySet() {
        return contextMatches.entrySet();
    }

    public Set<Entry<Integer, String>> methodsEntrySet() {
        return methodMatches.entrySet();
    }

    public boolean isValid(String value) {
        return !value.equals(INVALID_MATCH);
    }
}
