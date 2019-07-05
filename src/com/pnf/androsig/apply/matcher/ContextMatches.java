/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Represent a binding from an old classname to a new classname.
 * 
 * @author Cedric Lucas
 *
 */
public class ContextMatches {
    public static class CMatch {
        List<Match> matches = new ArrayList<>();
        boolean processed = false;
        String name = null;
    }

    public static class Match {
        String newName;
        int count;
        List<Integer> methodIndexes = new ArrayList<>();

        public Match(String newName) {
            this.newName = newName;
        }

        public void addMethod(Integer methodIndex) {
            count++;
            if(methodIndex != null) {
                // keep trace of wrong method indexes: were badly renamed, need to remove
                methodIndexes.add(methodIndex);
            }
        }
    }

    private final ILogger logger = GlobalLog.getLogger(ContextMatches.class);

    private static final String INVALID_MATCH = "INVALID";

    private Map<String, CMatch> contextMatches = new HashMap<>();

    private Map<Integer, String> methodMatches = new HashMap<>();

    public void saveParamMatching(String oldProto, String newProto, String className, Integer eMethodIndex,
            String methodName) {
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
        List<String> oldClasses = DexUtilLocal.parseSignatureParameters(tokens1[0]);
        oldClasses.add(tokens1[1]);
        List<String> newClasses = DexUtilLocal.parseSignatureParameters(tokens2[0]);
        newClasses.add(tokens2[1]);
        if(oldClasses.size() != newClasses.size()) {
            // parameter non use removed? too risky
            return;
        }
        for(int i = 0; i < oldClasses.size(); i++) {
            String oldClass = oldClasses.get(i);
            String newClass = newClasses.get(i);
            if(oldClass.endsWith(";")) {
                // return value updated
                while(oldClass.charAt(0) == '[') {
                    if(newClass.charAt(0) != '[') {
                        // argument swaps?
                        return;
                    }
                    oldClass = oldClass.substring(1);
                    newClass = newClass.substring(1);
                }
                saveClassMatch(oldClass, newClass, className, eMethodIndex, methodName);
            }
        }
    }

    private void saveClassMatch(String oldClass, String newClass, Integer eMethodIndex, BoundType type,
            String... params) {
        Boolean res = saveClassMatch(oldClass, newClass, eMethodIndex);
        if(res == Boolean.FALSE) {
            return; // interrupt
        }
        if(res == Boolean.TRUE) {
            switch(type) {
            case InnerClass:
                logger.debug("Found match class: %s related to innerClass %s", newClass, params[0]);
                break;
            case Inherit:
                logger.debug("Found match class: %s related to inherited %s", newClass, params[0]);
                break;
            case ParamMatching:
                logger.debug("Found match class: %s by param matching from %s->%s", newClass, params[0], params[1]);
                break;
            case UnknownSourceFile:
                logger.debug("Found match class: %s from different files", newClass);
                break;
            default:
                logger.debug("Found match class: %s", newClass);
                break;
            }
        }
        if(DexUtilLocal.isInnerClass(newClass)) {
            oldClass = DexUtilLocal.getParentSignature(oldClass);
            newClass = DexUtilLocal.getParentSignature(newClass);
            saveClassMatch(oldClass, newClass, eMethodIndex, type, params);
        }
    }

    private enum BoundType {
        InnerClass, Inherit, ParamMatching, UnknownSourceFile
    }

    public void saveClassMatch(String oldClass, String newClass, String innerClass) {
        saveClassMatch(oldClass, newClass, null, BoundType.InnerClass, innerClass);
    }

    public void saveClassMatchInherit(String oldClass, String newClass, String inherit) {
        saveClassMatch(oldClass, newClass, null, BoundType.Inherit, inherit);
    }

    public void saveClassMatch(String oldClass, String newClass, String className, Integer eMethodIndex,
            String methodName) {
        saveClassMatch(oldClass, newClass, eMethodIndex, BoundType.ParamMatching, className, methodName);
    }

    public void saveClassMatchUnkownFile(String oldClass, String newClass) {
        saveClassMatch(oldClass, newClass, null, BoundType.UnknownSourceFile);
    }

    public void setInvalidMethod(Integer key) {
        methodMatches.put(key, INVALID_MATCH);
    }

    private Match getMatch(CMatch value, String newName) {
        return getMatch(value.matches, newName);
    }

    private Match getMatch(List<Match> value, String newName) {
        for(Match val: value) {
            if(val.newName.equals(newName)) {
                return val;
            }
        }
        return null;
    }

    private Boolean saveClassMatch(String oldClass, String newClass, Integer methodIndex) {
        if (DexUtilLocal.getInnerClassLevel(oldClass) != DexUtilLocal.getInnerClassLevel(newClass)) {
            return Boolean.FALSE;
        }
        if(oldClass.charAt(0) != 'L' || newClass.charAt(0) != 'L') {
            return Boolean.FALSE;
        }
        CMatch value = contextMatches.get(oldClass);
        if(value == null) {
            value = new CMatch();
            contextMatches.put(oldClass, value);
        }
        Match val = getMatch(value, newClass);
        if(val == null) {
            val = new Match(newClass);
            value.matches.add(val);
        }
        val.addMethod(methodIndex);
        if(value.processed && !newClass.equals(value.name)) {
            // wrong class match attempt
            value.processed = false;
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    public boolean saveMethodMatch(Integer oldMethod, String newMethod) {
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

    public Set<String> keySet() {
        return new HashSet<>(contextMatches.keySet());
    }

    public CMatch get(String key) {
        return contextMatches.get(key);
    }

    public String getMethod(Integer key) {
        return methodMatches.get(key);
    }

    public Set<Entry<Integer, String>> methodsEntrySet() {
        return methodMatches.entrySet();
    }

    public boolean isValid(String value) {
        return !value.equals(INVALID_MATCH);
    }
}
