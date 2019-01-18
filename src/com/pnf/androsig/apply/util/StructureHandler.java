package com.pnf.androsig.apply.util;

import com.pnfsoftware.jeb.core.actions.ActionContext;
import com.pnfsoftware.jeb.core.actions.ActionCreatePackageData;
import com.pnfsoftware.jeb.core.actions.ActionMoveToPackageData;
import com.pnfsoftware.jeb.core.actions.ActionRenameData;
import com.pnfsoftware.jeb.core.actions.Actions;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;

public class StructureHandler {
    
    /**
     * Rename a method, class or package.
     * 
     * @param unit mandatory target unit
     * @param newName new name of a method, class or package
     * @param itemId target itemId of a method, class or package
     */
    public static void rename(IDexUnit unit, String newName, long itemId) {
        ActionRenameData data = new ActionRenameData();
        data.setNewName(newName);
        ActionContext action = new ActionContext(unit, Actions.RENAME, itemId);
        if(unit.prepareExecution(action, data)) {
            unit.executeAction(action, data, false);
        }
    }

    /**
     * Move a class.
     * 
     * @param unit mandatory target unit
     * @param packagePath path of the target package (targetPackage.getSignature(true))
     * @param itemId the itemId of the class
     */
    public static void moveClass(IDexUnit unit, String packagePath, long itemId) {
        String processedPath = packagePath.substring(1, packagePath.length() - 1).replace("/", ".");
        ActionMoveToPackageData data = new ActionMoveToPackageData();
        data.setDstPackageFqname(processedPath);
        ActionContext action = new ActionContext(unit, Actions.MOVE_TO_PACKAGE, itemId);
        if(unit.prepareExecution(action, data)) {
            unit.executeAction(action, data, false);
        }
    }

    /**
     * Create package.
     * 
     * @param unit mandatory target unit
     * @param packagePath path of the package to be created
     */
    public static void createPackage(IDexUnit unit, String packagePath) {
        String processedPath = packagePath.substring(1, packagePath.length() - 1).replace("/", ".");
        ActionCreatePackageData data = new ActionCreatePackageData();
        data.setFqname(processedPath);
        ActionContext action = new ActionContext(unit, Actions.CREATE_PACKAGE, 0);
        if(unit.prepareExecution(action, data)) {
            unit.executeAction(action, data, false);
        }
    }
}
