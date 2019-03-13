/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.common;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import com.pnf.androsig.JebContext;
import com.pnfsoftware.jeb.core.Artifact;
import com.pnfsoftware.jeb.core.IArtifact;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.ILiveArtifact;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.exceptions.JebException;
import com.pnfsoftware.jeb.core.input.FileInput;
import com.pnfsoftware.jeb.core.units.UnitUtil;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;

/**
 * @author Cedric Lucas
 *
 */
public class SignatureHandlerTest {

    @Test
    public void testHash() throws JebException, IOException {
        System.out.println("--------------------------");
        IEnginesContext context = JebContext.getEnginesContext();
        IRuntimeProject prj = context.loadProject("release.apk");
        File file = new File("testdata/apk", "app-release-unsigned.apk");
        IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
        ILiveArtifact art = prj.processArtifact(artifact);
        IDexUnit dex = UnitUtil.findChildByType(art.getMainUnit(), IDexUnit.class    , false, 0);
        assertNotNull(dex);
        
        //IDexClass cl = dex.getClass("Landroid/support/v4/app/BackStackRecord;");
        IDexMethod m = dex.getMethod("Landroid/support/v4/app/BackStackRecord;->bumpBackStackNesting(I)V");
        System.out.println("--------------------------");
        String hash = SignatureHandler.generateTightHashcode(m.getData().getCodeItem());
        System.out.println("--------------------------");
        assertEquals("78c5d86560b13cc8b03298cfe31af9791f9ac47f2de1b529a2d1d63ab7e3e47c", hash);
        hash = SignatureHandler.generateLooseHashcode(m.getData().getCodeItem());
        assertEquals("513dc391d69110db642082091bbe622d4ab0073cb34fa819af0f3742e84129f7", hash);
        System.out.println("--------------------------");
    }

    @Test
    public void testHash2() throws JebException, IOException {
        System.out.println("--------------------------");
        IEnginesContext context = JebContext.getEnginesContext();
        IRuntimeProject prj = context.loadProject("release.apk");
        File file = new File("testdata/apk", "app-release-unsigned--pg-repackageclasses.apk");
        IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
        ILiveArtifact art = prj.processArtifact(artifact);
        IDexUnit dex = UnitUtil.findChildByType(art.getMainUnit(), IDexUnit.class, false, 0);
        assertNotNull(dex);

        //IDexClass cl = dex.getClass("Landroid/support/v4/app/BackStackRecord;");
        IDexMethod m = dex.getMethod("Lcom/zzz/bn;->a(I)V");
        System.out.println("--------------------------");
        String hash = SignatureHandler.generateTightHashcode(m.getData().getCodeItem());
        assertNotEquals("78c5d86560b13cc8b03298cfe31af9791f9ac47f2de1b529a2d1d63ab7e3e47c", hash);
        System.out.println("--------------------------");
        hash = SignatureHandler.generateLooseHashcode(m.getData().getCodeItem());
        assertNotEquals("513dc391d69110db642082091bbe622d4ab0073cb34fa819af0f3742e84129f7", hash);
        System.out.println("--------------------------");
    }
}
