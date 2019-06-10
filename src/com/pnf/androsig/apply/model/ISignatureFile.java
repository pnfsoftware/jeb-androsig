/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.Closeable;
import java.util.List;

/**
 * @author Cedric Lucas
 *
 */
public interface ISignatureFile extends Closeable {

    LibraryInfo getLibraryInfos();

    List<MethodSignature> getTightSignatures(String hashcode);

    List<MethodSignature> getLooseSignatures(String hashcode);

    boolean hasSignaturesForClassname(String className);

    List<MethodSignature> getSignaturesForClassname(String className, boolean exactName);

    int getAllSignatureCount();

    List<MethodSignature> getParent(String className);

}
