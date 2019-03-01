/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;

/**
 * List of dex method hashcodes.
 * 
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
public class DexHashcodeList {

    private static final String[] EMPTY = new String[]{null, null};
    private Map<Integer, String[]> methodHashcodes = new HashMap<>();

    /**
     * Load all current apk hash codes.
     * 
     * @param unit mandatory target unit
     */
    public void loadAPKHashcodes(IDexUnit unit) {
        List<? extends IDexClass> classes = unit.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                continue;
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
                    methodHashcodes.put(m.getIndex(), EMPTY);
                }
                else {
                    methodHashcodes.put(m.getIndex(), new String[]{SignatureHandler.generateTightHashcode(ci),
                            SignatureHandler.generateLooseHashcode(ci)});
                }
            }
        }
    }

    public String getTightHashcode(IDexMethod method) {
        String[] hashcodes = methodHashcodes.get(method.getIndex());
        return hashcodes == null ? null: hashcodes[0];
    }

    public String getLooseHashcode(IDexMethod method) {
        String[] hashcodes = methodHashcodes.get(method.getIndex());
        return hashcodes == null ? null: hashcodes[1];
    }
}
