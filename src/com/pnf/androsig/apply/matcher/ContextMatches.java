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
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.base.JavaUtil;
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
                        saveMatch(oldClass, newClass, className, methodName);
                    }
                    oldClass = oldClass.substring(0, oldClass.lastIndexOf("$")) + ";";
                    newClass = newClass.substring(0, lastIndex) + ";";
                }
                if(!oldClass.equals(newClass)) {
                    saveMatch(oldClass, newClass, className, methodName);
                }
            }
        }
    }

    public void saveMatch(String oldClass, String newClass, String innerClass) {
        if(saveMatch(oldClass, newClass)) {
            logger.i("Found match class: %s related to innerClass %s", newClass, innerClass);
        }
    }

    public void saveMatch(String oldClass, String newClass, String className, String methodName) {
        if(saveMatch(oldClass, newClass)) {
            logger.i("Found match class: %s by param matching from %s->%s", newClass, className, methodName);
        }
    }

    private boolean saveMatch(String oldClass, String newClass) {
        String value = contextMatches.get(oldClass);
        if(value != null) {
            if(value.equals(INVALID_MATCH)) {
                return false;
            }
            else if(!value.equals(newClass)) {
                contextMatches.put(oldClass, INVALID_MATCH);
                return false;
            }
        }
        contextMatches.put(oldClass, newClass);
        return true;
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
        String[] expectedTokens = expected.split("->|\\(|\\)"); //0: classname, 1: methodname, 2: arguments, 3: return
        String[] currentTokens = current.split("->|\\(|\\)");
        if(expected.equals(current)) {
            methodMatches.put(m.getIndex(), expectedTokens[1]);
            return;
        }
        List<String> expectedParams = parseSignatureParameters(expectedTokens[2]);
        List<String> currentParams = parseSignatureParameters(currentTokens[2]);
        if(!areParamsSignatureCompatibles(expectedParams, currentParams, expectedTokens[3], currentTokens[3])) {
            return;
        }
        if(!expectedTokens[0].equals(currentTokens[0])) {
            saveMatch(currentTokens[0], expectedTokens[0]);
        }
        methodMatches.put(m.getIndex(), expectedTokens[1]);
        for(int i = 0; i < expectedParams.size(); i++) {
            if(!currentParams.get(i).equals(expectedParams.get(i))) {
                saveMatch(currentParams.get(i), expectedParams.get(i));
            }
        }

        if(!expectedTokens[3].equals(currentTokens[3])) {
            saveMatch(currentTokens[3], expectedTokens[3]);
        }
    }

    private boolean areParamsSignatureCompatibles(List<String> expectedParams, List<String> currentParams,
            String expectedReturn, String currentReturn) {
        if(expectedParams.size() != currentParams.size()) {
            return false;
        }
        if(!isSignatureCompatible(expectedReturn, currentReturn)) {
            return false;
        }
        for(int i = 0; i < expectedParams.size(); i++) {
            if(!isSignatureCompatible(expectedParams.get(i), currentParams.get(i))) {
                return false;
            }
        }
        return true;
    }

    private boolean isSignatureCompatible(String expected, String current) {
        int typeChar = 0;
        while(expected.charAt(typeChar) == '[' && current.charAt(typeChar) == '[') {
            typeChar++;
        }
        if(expected.charAt(typeChar) != current.charAt(typeChar)) {
            return false;
        }
        // TODO better validate a renaming has not been done
        // expected = expected.substring(typeChar);
        // current = current.substring(typeChar);
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
