/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.modules;

import java.util.List;
import java.util.Map;

import com.pnf.androsig.apply.matcher.ContextMatches;
import com.pnf.androsig.apply.matcher.DatabaseReferenceFile;
import com.pnf.androsig.apply.matcher.FileMatches;
import com.pnf.androsig.apply.matcher.IAndrosigModule;
import com.pnf.androsig.apply.matcher.IDatabaseMatcher;
import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;

/**
 * @author Cedric Lucas
 *
 */
public abstract class AbstractModule implements IAndrosigModule {
    private IDatabaseMatcher dbMatcher;
    private ContextMatches contextMatches = new ContextMatches();
    protected FileMatches fileMatches = new FileMatches();
    protected DatabaseReference ref;

    public AbstractModule(IDatabaseMatcher dbMatcher, ContextMatches contextMatches, FileMatches fileMatches,
            DatabaseReference ref) {
        super();
        this.dbMatcher = dbMatcher;
        this.contextMatches = contextMatches;
        this.fileMatches = fileMatches;
        this.ref = ref;
    }

    public List<MethodSignature> getSignaturesForClassname(String file, String className) {
        return ref.getSignaturesForClassname(file, className, true);
    }

    public List<MethodSignature> getSignaturesForClassname(DatabaseReferenceFile file, String className) {
        return ref.getSignaturesForClassname(file, className, true);
    }

    public DatabaseReferenceFile getFileFromClass(IDexClass dexClass) {
        return fileMatches.getFileFromClass(dexClass);
    }

    public DatabaseReferenceFile getFileFromClassId(int index) {
        return fileMatches.getFileFromClassId(index);
    }

    public boolean hasMatchedClass(Integer key) {
        return dbMatcher.getMatchedClasses().containsKey(key);
    }

    public Map<Integer, String> getMatchedClasses() {
        return dbMatcher.getMatchedClasses();
    }

    public void saveClassMatch(String oldClass, String newClass, String className, String methodName) {
        contextMatches.saveClassMatch(oldClass, newClass, className, methodName);
    }

    public void saveClassMatchInherit(String oldClass, String newClass, String inherit) {
        contextMatches.saveClassMatchInherit(oldClass, newClass, inherit);
    }

    public boolean saveMethodMatch(Integer oldMethod, String newMethod) {
        return contextMatches.saveMethodMatch(oldMethod, newMethod);
    }

    public void saveParamMatching(String oldProto, String newProto, String className, String methodName) {
        contextMatches.saveParamMatching(oldProto, newProto, className, methodName);
    }
}
