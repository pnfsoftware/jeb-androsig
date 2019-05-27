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

}
