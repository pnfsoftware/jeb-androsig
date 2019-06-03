/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.util;

import com.pnfsoftware.jeb.core.units.code.ICodeItem;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;

/**
 * @author Cedric Lucas
 *
 */
public class DexUtilLocal {

    public static boolean isInnerClass(String signature) {
        return signature.contains("$");
    }

    public static String getParentSignature(String signature) {
        return signature.substring(0, signature.lastIndexOf("$")) + ";";
    }

    public static IDexClass getParentClass(IDexUnit dex, String signature) {
        return dex.getClass(getParentSignature(signature));
    }

    public static int getInnerClassLevel(String signature) {
        int level = 0;
        for(int i = 0; i < signature.length(); i++) {
            if(signature.charAt(i) == '$') {
                level++;
            }
        }
        return level;
    }

    public static boolean isAnonymous(IDexClass eClass) {
        return (eClass.getGenericFlags() & ICodeItem.FLAG_ANONYMOUS) != 0;
    }

    public static boolean isAnonymous(String signature) {
        int from = signature.lastIndexOf("$") + 1;
        for(int i = from; i < signature.length() - 1; i++) {
            if(!Character.isDigit(signature.charAt(i))) {
                return false; // normally, first char must not be digit for java Class but check all
            }
        }
        return true;
    }

    /**
     * Compare unmutable method names (init and clinit). Do not need signatures since constructors
     * names do not change with signature.
     * 
     * @param name1
     * @param name2
     * @return
     */
    public static boolean isMethodCompatible(String name1, String name2) {
        if("<init>".equals(name1) != "<init>".equals(name2)
                || "<clinit>".equals(name1) != "<clinit>".equals(name2)) {
            return false;
        }
        return true;
    }

    public static boolean isMethodCompatibleWithSignatures(String name1, String sig1, String name2, String sig2) {
        String params1 = extractParamsFromSignature(sig1);
        String params2 = extractParamsFromSignature(sig2);
        return isMethodCompatibleWithParams(name1, params1, name2, params2);
    }

    public static boolean isMethodCompatibleWithParams(String name1, String params1, String name2, String params2) {
        if(!isMethodCompatible(name1, name2)) {
            return false;
        }
        if(!compareMethodWithoutParameter("toString", name1, params1, name2, params2)
                || !compareMethodWithParameters("equals", "Ljava/lang/Object;", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("finalize", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("getClass", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("hashCode", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("notify", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("notifyAll", name1, params1, name2, params2)
                || !compareMethodWithoutParameter("wait", name1, params1, name2, params2)
                || !compareMethodWithParameters("wait", "J", name1, params1, name2, params2)
                || !compareMethodWithParameters("wait", "JI", name1, params1, name2, params2)) {
            return false;
        }
        return true;
    }

    public static String extractParamsFromSignature(String sig) {
        int start = sig.indexOf("(");
        int end = sig.indexOf(")");
        if(start < 0 || end < 0 || start >= end) {
            throw new IllegalArgumentException("Illegal signature " + sig);
        }
        return sig.substring(start + 1, end);
    }

    private static boolean compareMethodWithoutParameter(String methodName, String name1, String params1, String name2,
            String params2) {
        return (methodName.equals(name1) && params1.length() == 0) == (methodName.equals(name2)
                && params2.length() == 0);
    }

    private static boolean compareMethodWithParameters(String methodName, String methodParams, String name1,
            String params1, String name2, String params2) {
        return (methodName.equals(name1) && methodParams.equals(params1)) == (methodName.equals(name2)
                && methodParams.equals(params2));
    }
}
