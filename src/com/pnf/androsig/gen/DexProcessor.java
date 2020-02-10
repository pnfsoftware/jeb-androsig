/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.gen;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.ICodeType;
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
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
public class DexProcessor {
    private static final ILogger logger = GlobalLog.getLogger(DexProcessor.class);

    private String classnameFilter;
    private int methodCount = 0;

    private Map<Integer, Map<Integer, Integer>> allCallerLists = new HashMap<>();
    private Map<Integer, String> sigMap = new HashMap<>();
    private Map<Integer, String> hierarchyMap = new HashMap<>();

    /**
     * @param classnameFilter regular expression of classes to be processed
     */
    public DexProcessor(String classnameFilter) {
        this.classnameFilter = classnameFilter;
    }

    public boolean processDex(IDexUnit dex) {
        if(!dex.isProcessed()) {
            if(!dex.process()) {
                return false;
            }
        }
        List<? extends IDexClass> classes = dex.getClasses();
        if(classes == null || classes.size() == 0) {
            logger.info("No classes in current project");
            return false;
        }
        Pattern p = null;
        if(!Strings.isBlank(classnameFilter)) {
            p = Pattern.compile(classnameFilter);
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                continue;
            }
            String classname = eClass.getClassType().getSignature(true);
            if(p != null && !p.matcher(classname).matches()) {
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

                String mhash_tight = new String();
                String mhash_loose = new String();
                int opcount = 0;

                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    mhash_tight = "";
                    mhash_loose = "";
                }
                else {
                    mhash_tight = SignatureHandler.generateTightHashcode(ci);
                    mhash_loose = SignatureHandler.generateLooseHashcode(ci);
                    SignatureHandler.loadCallerList(dex, allCallerLists, ci, m);// Store all callers
                    opcount = ci.getInstructions().size();
                }
                if(mhash_tight == null || mhash_loose == null) {
                    continue;
                }
                StringBuilder s = new StringBuilder();
                s.append(classname).append(',');
                s.append(m.getName(true)).append(',');
                IDexPrototype proto = dex.getPrototype(m.getPrototypeIndex());
                s.append(proto.getShorty()).append(',');
                s.append(proto.generate(false)).append(',');
                s.append(opcount).append(',');
                s.append(mhash_tight).append(',');
                s.append(mhash_loose);

                sigMap.put(m.getIndex(), s.toString());

                methodCount++;
            }
            // add hierarchy
            List<? extends ICodeType> superTypes = eClass.getSupertypes();
            List<? extends ICodeType> interfaces = eClass.getImplementedInterfaces();
            StringBuilder s = new StringBuilder();
            s.append(classname).append(",<parent>,,,0,,,");
            StringBuilder ss = new StringBuilder();
            if(superTypes != null && !superTypes.isEmpty()) {
                if(!(superTypes.size() == 1 && superTypes.get(0).getSignature(true).equals("Ljava/lang/Object;"))) {
                    for(ICodeType su: superTypes) {
                        ss.append(su.getSignature(true)).append('|');
                    }
                    ss.deleteCharAt(ss.length() - 1);
                }
            }
            StringBuilder si = new StringBuilder();
            if(interfaces != null && !interfaces.isEmpty()) {
                for(ICodeType su: interfaces) {
                    si.append(su.getSignature(true)).append('|');
                }
                si.deleteCharAt(si.length() - 1);
            }
            if(ss.length() != 0 || si.length() != 0) {
                s.append(ss).append("||").append(si);
            }
            hierarchyMap.put(eClass.getIndex(), s.toString());
        }
        return true;
    }

    public int getMethodCount() {
        return methodCount;
    }

    public Map<Integer, Map<Integer, Integer>> getAllCallerLists() {
        return allCallerLists;
    }

    public Map<Integer, String> getSigMap() {
        return sigMap;
    }

    public Map<Integer, String> getHierarchyMap() {
        return hierarchyMap;
    }

}
