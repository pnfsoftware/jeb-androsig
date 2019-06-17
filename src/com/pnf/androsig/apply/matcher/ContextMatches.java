/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.HashMap;
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
    private final ILogger logger = GlobalLog.getLogger(ContextMatches.class);

    private static final String INVALID_MATCH = "INVALID";

    private Map<String, String> contextMatches = new HashMap<>();

    private Map<Integer, String> methodMatches = new HashMap<>();

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

    public void saveClassMatchUnkownFile(String oldClass, String newClass) {
        if(saveClassMatch(oldClass, newClass) == Boolean.TRUE) {
            logger.debug("Found match class: %s from different files", newClass);
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
