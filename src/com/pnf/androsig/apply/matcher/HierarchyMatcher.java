/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.List;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.util.base.Couple;
import com.pnfsoftware.jeb.util.format.Strings;

/**
 * @author Cedric Lucas
 *
 */
public class HierarchyMatcher {
    private String origin;
    private List<String> interfaces;

    public HierarchyMatcher(IDexClass eClass) {
        origin = eClass.getSupertypes().get(0).getSignature(true);
        interfaces = eClass.getImplementedInterfaces().stream().map(c -> c.getSignature(true))
                .collect(Collectors.toList());
    }

    public String getSuperType() {
        return origin;
    }

    public List<String> getInterfaces() {
        return interfaces;
    }

    public boolean isCompatible(DatabaseReference ref, DatabaseReferenceFile file, String className) {
        Couple<String, List<String>> hierarchy = ref.getParentForClassname(file, className);
        if(hierarchy == null) {
            // no hierarchy data or bad form
            return true;
        }
        String supertype = hierarchy.getFirst();
        if(supertype != null) {
            if(!isCompatibleSuperType(supertype)) {
                return false;

            }
        }
        List<String> interfacesTest = hierarchy.getSecond();
        boolean voidInterfaces = interfaces == null || interfaces.isEmpty();
        boolean voidInterfacesTest = interfacesTest == null || interfacesTest.isEmpty();
        if(voidInterfaces && voidInterfacesTest) {
            return true;
        }
        else if(voidInterfacesTest) {
            // TODO merge, pick correct one
            return true;
        }
        else if(voidInterfaces != voidInterfacesTest) {
            return false;
        }
        if(interfacesTest.size() == 1 && interfaces.size() == 1) {
            return isCompatibleClass(interfacesTest.get(0), interfaces.get(0));
        }
        else {
            for(String inter: interfaces) {
                boolean found = false;
                for(String interTest: interfacesTest) {
                    if(isCompatibleClass(interTest, inter)) {
                        found = true;
                        break;
                    }
                }
                if(!found) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isCompatibleSuperType(String supertype) {
        return isCompatibleClass(supertype, origin);
    }

    private boolean isCompatibleClass(String unstable, String original) {
        if(Strings.isBlank(original)) {
            if(Strings.isBlank(unstable)) {
                // compatible
            }
            else {
                // type added by obfuscation?
                System.out.println();
            }
        }
        else {
            if(Strings.isBlank(unstable)) {
                // type removed by obfuscation?
                System.out.println();
            }
            else {
                if(!DexUtilLocal.isCompatibleClasses(original, unstable)) {
                    return false;
                }
            }
        }
        return true;

    }
}
