/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.util.HashMap;
import java.util.Map;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.serialization.annotations.Ser;
import com.pnfsoftware.jeb.util.serialization.annotations.SerId;

/**
 * @author Cedric Lucas
 *
 */
@Ser
public class StructureResult implements IStructureResult {

    // method map (method.getSignature(false), method.getSignature(true))
    // used by DexMetadataGroup
    @SerId(1)
    private Map<String, String> matchedMethods_new_orgPath = new HashMap<>();
    @SerId(2)
    private Map<String, String> matchedClasses_new_orgPath = new HashMap<>();

    @Override
    public Map<String, String> getMatchedMethods_new_orgPath() {
        return matchedMethods_new_orgPath;
    }

    @Override
    public Map<String, String> getMatchedClasses_new_orgPath() {
        return matchedClasses_new_orgPath;
    }

    public void storeAllMatchedMethods_new_orgPath(IDexUnit unit, Map<Integer, String> matchedMethods) {
        for(int each: matchedMethods.keySet()) {
            IDexMethod method = unit.getMethod(each);
            matchedMethods_new_orgPath.put(method.getSignature(true), method.getSignature(false));
        }
    }

    public void storeAllMatchedClasses_new_orgPath(IDexUnit unit, Map<Integer, String> matchedClasses) {
        for(int each: matchedClasses.keySet()) {
            IDexClass eClass = unit.getClass(each);
            matchedClasses_new_orgPath.put(eClass.getSignature(true), eClass.getSignature(false));
        }
    }

}
